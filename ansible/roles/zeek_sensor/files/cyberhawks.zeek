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
event connection_established(c: connection) {
    if (c$id$resp_p == 389/tcp || c$id$resp_p == 636/tcp || c$id$resp_p == 9389/tcp)
        Log::write(ConnOpen::LOG, [$ts=network_time(), $uid=c$uid, $id=c$id]);
}
