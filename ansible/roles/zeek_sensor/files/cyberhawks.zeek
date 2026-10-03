# CyberHawks site policy, deployed by the zeek_sensor role and loaded from
# local.zeek. Only settings the splunk-detections searches depend on live
# here; everything else stays on Zeek's defaults.

# Mirrored/SPAN capture (2026-09-30). This sensor analyzes copies of packets
# mirrored from every guest's tap. The range's virtio NICs offload checksum
# computation to the host, so a mirrored copy of an outbound packet carries an
# incomplete/blank checksum that looks invalid to Zeek. By default Zeek drops
# such packets before L4 reassembly -- conn.log (header-only) still records the
# flow, but the Kerberos/DCE-RPC/LDAP application analyzers never see reassembled
# payload and emit nothing. Only router-crossing traffic (re-checksummed by
# pfSense) decoded, which is why kerberos.log was empty for all same-vnet
# Kerberos and the S4U `impersonated` field was only recoverable for the
# john-kali path. On a mirror sensor the checksums are not ours to validate, so
# analyze the copies as-is. This restores kerberos/dce_rpc/ldap decode on every
# path.
redef ignore_checksums = T;

# Detection latency (2026-09-30). Zeek writes a conn.log record when a flow
# ends, and a UDP or ICMP flow only "ends" once it has been idle this long.
# At the 1 minute default every UDP/ICMP detection (Ping Sweep, Name
# Resolution Poisoning, UDP port scans) waited ~62s for its conn record.
# A TCP flow is likewise held after its SYN goes unanswered, its RST, or its
# FIN close (5s defaults each) before the record is written. All of these
# are 1s here, so a finished flow reaches conn.log in ~1-2s instead of ~6s
# (the RTT on this LAN is well under a millisecond, so 1s is still ample for
# a SYN-ACK or a final ACK). The only side effect is that a flow with a >1s
# gap is logged as two records instead of one; the conn.log detections count
# distinct hosts or ports, or pair records by their own timestamps, so
# splitting is harmless.
redef udp_inactivity_timeout = 1 secs;
redef icmp_inactivity_timeout = 1 secs;
redef tcp_SYN_timeout = 1 secs;
redef tcp_attempt_delay = 1 secs;
redef tcp_reset_delay = 1 secs;
redef tcp_close_delay = 1 secs;
# Log writers buffer records and flush on this interval (default 1s).
redef Log::flush_interval = 250 msec;

# Immediate connection-open log for the directory-service ports, written the
# moment the TCP handshake completes rather than when the flow closes (which is
# what conn.log waits for -- up to 5 min for a held-open session). The LDAP
# Query detection anchors on the DC's 1644 event (which has the client IP for
# LDAP/LDAPS but only loopback for ADWS, since ADWS runs the search on the DC
# over loopback). This log gives that detection, at query time:
#   - the ADWS (9389) client's real IP, joined by DC + time, and
#   - the connection's destination port, so a 1644 can be labelled ldap (389)
#     vs ldaps (636) -- the 1644 itself does not say which.
# conn.log can't do this: it is written on close, so it arrives too late (and
# for a pooled ADWS session, much too late). Volume is negligible (~a few
# hundred connections a day, all directory-service ports; measured 2026-09-30).
# Columns match conn.log's names (id.orig_h/id.resp_h/id.resp_p) via the
# conn_id record, so the Splunk field extraction mirrors zeek:conn.
module ConnOpen;
export {
    redef enum Log::ID += { LOG };
    type Info: record {
        ts: time &log;
        uid: string &log;
        id: conn_id &log;
    };
}
event zeek_init() {
    Log::create_stream(ConnOpen::LOG, [$columns=Info, $path="conn_open"]);
}
#
# WinRM (5985/5986) added 2026-10-02 for the same reason: on the two Windows
# Server 2016 hosts (dc1, sql1, build 14393) WinRM/Operational event 91 is
# written with no data at all -- no ResourceUri and no "clientIP" -- and a
# WinRM network logon's 4624 has no source address on any host, so an action
# taken through a WinRM session there could not be tied to an IP. Lateral
# Movement: WinRM was blind on those two hosts and Password Change attributed
# a WinRM-driven reset to the DC itself. They now take the client from the
# latest WinRM connection open to that host just before the session. Volume:
# ~750 WinRM connections/day (nearly all this project's own administration),
# ~65 bytes each.
event connection_established(c: connection) {
    if (c$id$resp_p == 389/tcp || c$id$resp_p == 636/tcp || c$id$resp_p == 9389/tcp
        || c$id$resp_p == 5985/tcp || c$id$resp_p == 5986/tcp)
        Log::write(ConnOpen::LOG, [$ts=network_time(), $uid=c$uid, $id=c$id]);
}

# Broadcast ARP request log for the ARP Scan detection (2026-10-02). Zeek has
# no ARP log of its own. A host discovering who is alive on its own subnet
# (nmap -sn/-PR, arp-scan, netdiscover) has to broadcast a who-has for every
# address, because it doesn't know their MACs yet; ordinary hosts mostly send
# unicast cache-refresh requests to MACs they already know. So only broadcast
# requests are logged, which is all ARP Scan needs. Measured on the mirror
# feed before enabling: 69 ARP requests in 10 minutes, 5 of them broadcast,
# i.e. ~700 lines (~70 KB) a day, versus ~1 MB/day for every request. ARP
# probes (sender 0.0.0.0, duplicate-address detection) and gratuitous ARP
# (sender == target, an address announcement) are not lookups of other hosts
# and are skipped. Columns: the sender's MAC and IP, and the IP asked for.
module ArpRequest;
export {
    redef enum Log::ID += { LOG };
    type Info: record {
        ts: time &log;
        orig_mac: string &log;
        orig_h: addr &log;
        resp_h: addr &log;
    };
}
event zeek_init() {
    Log::create_stream(ArpRequest::LOG, [$columns=Info, $path="arp_request"]);
}
event arp_request(mac_src: string, mac_dst: string, SPA: addr, SHA: string, TPA: addr, THA: string) {
    if (mac_dst != "ff:ff:ff:ff:ff:ff" || SPA == 0.0.0.0 || SPA == TPA)
        return;
    Log::write(ArpRequest::LOG, [$ts=network_time(), $orig_mac=mac_src, $orig_h=SPA, $resp_h=TPA]);
}

# MAC addresses on name-resolution flows only (2026-10-02), for Name
# Resolution Poisoning. A poisoner such as Responder answers a victim's
# IPv4 AND IPv6 (link-local) queries, so by IP alone one attack looked like two
# attackers (10.0.2.10 and fe80::be24:11ff:fef4:c79) and posted two alerts.
# Both answers carry the same source MAC, so the detection groups by MAC and
# reports the IPv4 address. Zeek's stock policy/protocols/conn/mac-logging
# would add both MACs to every conn.log line (~2.6 MB/day here); this fills
# them only for LLMNR (5355), mDNS (5353) and NBNS (137) flows, leaving "-"
# elsewhere (~0.3 MB/day). Same column names as the stock policy, appended to
# the end of conn.log, so the Splunk field list just gains two trailing names.
redef record Conn::Info += {
    orig_l2_addr: string &log &optional;
    resp_l2_addr: string &log &optional;
};
const name_resolution_ports: set[port] = { 5355/udp, 5353/udp, 137/udp };
event connection_state_remove(c: connection) {
    if (c$id$resp_p !in name_resolution_ports && c$id$orig_p !in name_resolution_ports)
        return;
    if (c$orig?$l2_addr)
        c$conn$orig_l2_addr = c$orig$l2_addr;
    if (c$resp?$l2_addr)
        c$conn$resp_l2_addr = c$resp$l2_addr;
}
