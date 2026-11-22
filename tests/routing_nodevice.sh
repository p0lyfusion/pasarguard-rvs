#!/bin/sh
# Runs as the shell of a session started without a device.
echo "== no device yet: 8.8.8.8 -> (expect prohibit / error)"; ip route get 8.8.8.8 2>&1
echo "== no device yet: helper uid -> (expect via eth0)"; ip route get 203.0.113.1 uid 7777
echo "== rvs select -d 42.8 (expect only an add on fake2, nothing to remove)"; rvs select -d 42.8
echo "== 8.8.8.8 -> (expect dev rvstun0)"; ip route get 8.8.8.8
