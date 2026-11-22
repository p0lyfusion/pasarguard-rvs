#!/bin/sh
# Runs as the session's "shell": inspect routing, select another device, simulate an xray crash.
xray_pid() { for p in /proc/[0-9]*; do [ "$(cat "$p/comm" 2>/dev/null)" = xray ] && echo "${p#/proc/}"; done; }
echo "== inside session: ip rule (expect fwmark 0x77 and uidrange 7777 -> 77)"; ip rule
echo "== routes"; ip route
echo "== 8.8.8.8 -> (expect dev rvstun0)"; ip route get 8.8.8.8
echo "== node 203.0.113.1 from the shell -> (expect dev rvstun0: not pinned)"; ip route get 203.0.113.1
echo "== node with xray's mark -> (expect via gateway dev eth0)"; ip route get 203.0.113.1 mark 0x77
echo "== node as the helper uid -> (expect via gateway dev eth0)"; ip route get 203.0.113.1 uid 7777
echo "== resolv.conf (expect 1.1.1.1)"; cat /etc/resolv.conf
before=$(xray_pid)
echo "== rvs select -d 42.8 --dry-run (expect the plan for fake2, nothing changed)"
rvs select -d 42.8 --dry-run | grep -E '"node"|ruleTag|"address"'
echo "== xray pid still $(xray_pid) (expect $before)"
echo "== rvs select -d 42.8 (expect: rule 42.7 removed on fake1, then 42.8 added on fake2)"
rvs select -d 42.8
after=$(xray_pid)
echo "== xray pid $before -> $after (expect different)"
echo "== 8.8.8.8 after select -> (expect dev rvstun0)"; ip route get 8.8.8.8
echo "== rvs select -d 99.1 (expect an error, still on 42.8)"; rvs select -d 99.1
echo "== kill xray (simulated crash)"
kill -9 $(xray_pid)
sleep 1
echo "== 8.8.8.8 after crash -> (expect prohibit / error)"; ip route get 8.8.8.8 2>&1
echo "== helper uid after crash -> (expect still via eth0)"; ip route get 203.0.113.1 uid 7777
echo "== rvs select -d 42.7 after the crash (expect a new xray, rvstun0 again)"; rvs select -d 42.7
echo "== xray pid now $(xray_pid)"; ip route get 8.8.8.8
