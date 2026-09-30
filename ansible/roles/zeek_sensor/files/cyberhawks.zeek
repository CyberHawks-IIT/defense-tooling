# CyberHawks site policy, deployed by the zeek_sensor role and loaded from
# local.zeek. Only settings the splunk-detections searches depend on live
# here; everything else stays on Zeek's defaults.

# Detection latency (2026-09-30). Zeek writes a conn.log record when a flow
# ends, and a UDP or ICMP flow only "ends" once it has been idle this long.
# At the 1 minute default every UDP/ICMP detection (Ping Sweep, Name
# Resolution Poisoning, UDP port scans) waited ~62s for its conn record.
# At 5s they wait ~6s, the same as TCP (whose close/attempt delays are 5s).
# The only side effect is that a UDP/ICMP exchange with a >5s gap is logged
# as two records instead of one; those detections count distinct hosts or
# ports, or pair records by their own timestamps, so splitting is harmless.
redef udp_inactivity_timeout = 5 secs;
redef icmp_inactivity_timeout = 5 secs;

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
