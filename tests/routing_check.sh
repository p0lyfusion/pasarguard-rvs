#!/bin/sh
# Runs as the session's "shell": inspect routing, select another device, simulate an xray crash.
xray_pid() { for p in /proc/[0-9]*; do [ "$(cat "$p/comm" 2>/dev/null)" = xray ] && echo "${p#/proc/}"; done; }
echo "== shell: uid $(id -u) (expect 0); CapEff = CapBnd (expect yes): $(
  [ "$(grep CapEff /proc/$$/status | cut -f2)" = "$(grep CapBnd /proc/$$/status | cut -f2)" ] && echo yes || echo NO)"
echo "== xray runs as uid (expect 7777): $(awk '/^Uid:/ {print $2}' /proc/$(xray_pid)/status)"
echo "== inside session: ip rule (expect uidrange 7777 -> 77)"; ip rule
echo "== routes"; ip route
echo "== 8.8.8.8 -> (expect dev rvstun0)"; ip route get 8.8.8.8
echo "== node 203.0.113.1 from the shell -> (expect dev rvstun0: not pinned)"; ip route get 203.0.113.1
echo "== node as rvs's uid -> (expect via gateway dev eth0)"; ip route get 203.0.113.1 uid 7777
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
echo "== another session routes user 42 on fake1: rvs select -d 42.7 (expect refused, then no device)"
echo "rvs-shell-42.9-other1 r-42.9" > /tmp/foreign-fake1
rvs select -d 42.7
echo "== 8.8.8.8 -> (expect prohibit / error: blocked, not leaking)"; ip route get 8.8.8.8 2>&1
echo "== rvs select -d 42.7 --take-over (expect other1's rule removed, ours added)"; rvs select -d 42.7 --take-over
echo "== foreign rules left on fake1 (expect none): [$(cat /tmp/foreign-fake1)]"
echo "== another session steals user 42 on fake1 (its rule matches first): watchdog (expect a block within ~1s)"
echo "rvs-shell-42.9-other2 r-42.9" > /tmp/foreign-fake1
sleep 3
echo "== 8.8.8.8 -> (expect prohibit / error)"; ip route get 8.8.8.8 2>&1
rm -f /tmp/foreign-fake1
echo "== rvs select -d 42.8 (fake2, nothing there: expect it works)"; rvs select -d 42.8
echo "== kill xray (simulated crash)"
kill -9 $(xray_pid)
sleep 1
echo "== 8.8.8.8 after crash -> (expect prohibit / error)"; ip route get 8.8.8.8 2>&1
echo "== rvs's uid after crash -> (expect still via eth0)"; ip route get 203.0.113.1 uid 7777
echo "== rvs select -d 42.7 after the crash (expect a new xray, rvstun0 again)"; rvs select -d 42.7
echo "== xray pid now $(xray_pid)"; ip route get 8.8.8.8
