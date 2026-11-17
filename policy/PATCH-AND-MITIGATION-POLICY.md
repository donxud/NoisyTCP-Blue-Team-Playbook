# Patch and Mitigation Policy: NoisyTCP (CVE-2026-99288)

| Host category | Patch deadline | If it cannot be patched in time |
|---|---|---|
| Internet-facing, multi-queue or RPS, any TCP listener | 72 hours from vendor kernel availability | Workaround within 24 h of approval, edge SYN-flood protection, P1 monitoring |
| Internal, exposed to many users or networks (jump hosts, shared services, container hosts) | 7 days | Workaround if a reboot is not possible within 7 days |
| Internal, limited exposure | 30 days | Monitoring only |
| Single receive queue and no RPS (precondition absent) | Next normal window | Re-check after any NIC or kernel tuning change |
| RHEL 6/7, CentOS 7 kernels | Not affected by this CVE | None for this CVE (but these are end of life) |

## Rules

1. **Verify the booted kernel, not the installed package.** A patched package does nothing until the host reboots into it.
2. **Check the package against the vendor advisory.** Distribution kernels backport fixes under older version numbers; `uname -r` alone does not prove anything.
3. **arm64 and POWER:** confirm both commits, 4e2b3ef19e0e and 5b5d8f351dd9. The second was not in upstream 6.12.117, 6.18.63 or 7.3.4.
4. **Container hosts:** a kernel panic takes down every tenant. Treat them as the top internal category. SYN-cookie workarounds must be applied in each network namespace.
5. **Workarounds are temporary.** Each one needs a change ticket, an owner and an expiry date. Roll back after the fix is verified; `tcp_syncookies=0` removes SYN-flood protection.
6. **Exceptions** need written risk acceptance from the service owner and the security officer, with a review date no more than 30 days out.
