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
