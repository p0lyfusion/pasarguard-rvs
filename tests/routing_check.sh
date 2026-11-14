#!/bin/sh
# Runs as the session's "shell": inspect routing, simulate an xray crash, check the kill switch.
echo "== inside session: routes"; ip route
echo "== 8.8.8.8 -> (expect dev rvstun0)"; ip route get 8.8.8.8
echo "== node 203.0.113.1 -> (expect via gateway dev eth0)"; ip route get 203.0.113.1
echo "== resolv.conf (expect 1.1.1.1)"; cat /etc/resolv.conf
echo "== kill xray (simulated crash)"
for p in /proc/[0-9]*; do [ "$(cat "$p/comm" 2>/dev/null)" = xray ] && kill -9 "${p#/proc/}"; done
sleep 1
echo "== 8.8.8.8 after crash -> (expect prohibit / error)"; ip route get 8.8.8.8 2>&1
echo "== node after crash -> (expect still via eth0)"; ip route get 203.0.113.1
