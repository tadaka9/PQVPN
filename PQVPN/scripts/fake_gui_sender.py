#!/usr/bin/env python3
"""Fake node sender for GUI IPC testing.
Sends newline-delimited JSON messages to /tmp/pqvpn_gui.sock (or $PQVPN_GUI_SOCKET).
Run this after starting the GUI to observe peers, METRICS, HS_FAIL handling.
"""

import socket
import os
import json
import time
import sys

sock_path = os.environ.get("PQVPN_GUI_SOCKET", "/tmp/pqvpn_gui.sock")
if not os.path.exists(sock_path):
    print("GUI socket not found:", sock_path)
    sys.exit(1)


def send(obj):
    try:
        s = socket.socket(socket.AF_UNIX, socket.SOCK_STREAM)
        s.connect(sock_path)
        s.sendall((json.dumps(obj) + "\n").encode())
        s.close()
        print("sent", obj)
    except Exception as e:
        print("send failed", e)


# send a summary
send(
    {
        "type": "METRICS_SUMMARY",
        "ts": int(time.time()),
        "node": "fake-node",
        "sessions": 1,
        "peers": 2,
        "packets_rx": 10,
        "packets_tx": 5,
        "errors": 0,
    }
)
# send per-peer metrics
for peer in ["C8-2ZtOvN4k", "E-dOWPvObyU"]:
    send(
        {
            "type": "METRICS",
            "ts": int(time.time()),
            "peer": peer,
            "peer_full": "dummy",
            "addr": "127.0.0.1:5556",
            "bytes_sent": 100,
            "bytes_recv": 200,
            "packets": 3,
        }
    )
    time.sleep(0.2)
# simulate a HS_FAIL for first peer
send(
    {
        "type": "HS_FAIL",
        "ts": int(time.time()),
        "peer": "C8-2ZtOvN4k",
        "reason": "InvalidTag",
        "details": {"payload_snippet": "deadbeef"},
    }
)
print("done")
