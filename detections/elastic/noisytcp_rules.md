# NoisyTCP (CVE-2026-99288) rules for Elastic Security

Field names assume the Elastic Agent **System** integration (`system.syslog`) or the **Auditd** integration, mapped to ECS. Adjust `event.dataset` to your data.

## Rule 1 — Kernel oops in the TCP receive path (High)

Rule type: **Custom query**, every 5 min, look-back 10 min.

```
event.dataset:("system.syslog" or "journald") and process.name:"kernel" and
message:("tcp_v4_rcv" or "tcp_v6_rcv") and
message:("NULL pointer dereference" or "Oops" or "Fatal exception in interrupt")
```

The trace spans several lines, so also deploy this as an **EQL sequence** where your pipeline splits lines:

```eql
sequence by host.name with maxspan=30s
  [any where message : "*NULL pointer dereference*"]
  [any where message : ("*tcp_v4_rcv*", "*tcp_v6_rcv*")]
```

## Rule 2 — SYN backlog overflow precursor (Medium)

Rule type: **Threshold**, group by `host.name`, threshold 1, every 15 min.

```
event.dataset:("system.syslog" or "journald") and message:"Possible SYN flooding on port"
```

Raise to High with an **indicator match** or enrichment against an index of `noisytcp_check.sh` results where `status` is `EXPOSED` or `UNKNOWN`.

## Rule 3 — Mitigation drift (Medium)

Rule type: **Custom query** on auditd data.

```
event.dataset:"auditd.log" and auditd.message_type:"execve" and
((process.name:"sysctl" and process.args:(*tcp_syncookies* or *rps_sock_flow_entries*)) or
 (process.name:"ethtool" and process.args:("-L" or "--set-channels")))
```

## Rule 4 — Exposure status (Info)

Ship `noisytcp_check.sh` JSON output with Filebeat/Agent (custom logs, JSON parsing) to `logs-noisytcp.check-*`, then:

```
data_stream.dataset:"noisytcp.check" and status:("EXPOSED" or "UNKNOWN")
```
