# ADB Emulator Access from Orchestrator Pod

**Labels:** `documentation`, `adb`
**Ticket:** `beadhub-hr46`

## Overview

The orchestrator pod can connect to an Android emulator running on a developer's desktop via ADB over the network. This enables agents to interact with mobile apps (start/stop emulator, take screenshots, run shell commands) without needing SSH or GUI access.

## Prerequisites

- ADB is included in the agent image (`android-tools-adb` — added in `beadhub-m5x7`)
- The emulator must be running on the desktop and ADB over TCP must be enabled (port 5555)
- The emulator console port must be open (port 5554) for GPU screenshots
- Windows Firewall rules must allow inbound TCP on ports 5554 and 5555

### Windows Firewall Rules (run in PowerShell on desktop)

```powershell
New-NetFirewallRule -DisplayName "Android Emulator ADB 5555" -Direction Inbound -Protocol TCP -LocalPort 5555 -Action Allow
New-NetFirewallRule -DisplayName "Android Emulator Console 5554" -Direction Inbound -Protocol TCP -LocalPort 5554 -Action Allow
```

## Connecting via ADB

```bash
adb connect <desktop-ip>:5555
adb devices
```

Example (Woodson's desktop):
```bash
adb connect 192.168.2.13:5555
# → connected to 192.168.2.13:5555
```

## Taking Screenshots

### Why not `adb screencap`?

`adb exec-out screencap -p` returns a black image when the emulator uses GPU/hardware rendering (the default). The framebuffer is not accessible via ADB in this mode.

### Correct method: Emulator Console (`screenrecord screenshot`)

The emulator console (port 5554) captures directly from the GPU and always produces a real screenshot.

**Step 1 — Find your auth token** (on the desktop):
```
C:\Users\<username>\.emulator_console_auth_token
```

**Step 2 — Connect via Python socket and take screenshot:**

```python
import socket, time

s = socket.socket()
s.connect(('<desktop-ip>', 5554))
s.settimeout(5)

def recv(s):
    buf = b''
    try:
        while True:
            chunk = s.recv(4096)
            if not chunk: break
            buf += chunk
    except: pass
    return buf.decode(errors='replace')

time.sleep(0.5); recv(s)
s.sendall(b'auth <your-auth-token>\r\n')
time.sleep(0.5); recv(s)
s.sendall(b'screenrecord screenshot /sdcard/screen.png\r\n')
time.sleep(3); recv(s)
s.sendall(b'quit\r\n')
s.close()
```

**Step 3 — Pull the file via ADB:**
```bash
adb -s <desktop-ip>:5555 pull /sdcard/screen.png /tmp/screen.png
```

A real screenshot will be **50KB–500KB**. A black/empty screen is typically **<15KB**.

## Sending Screenshots to Discord

Push a message to Redis `orchestrator:outbox` with a base64-encoded attachment. Always fetch the **current thread ID** first — it changes with each new message from the user.

```python
import json, base64, socket

# Get current thread ID from Redis first
# kubectl exec -n beadhub redis-... -- redis-cli GET "ordis:thread:<session-id>"

with open('/tmp/screen.png', 'rb') as f:
    b64 = base64.b64encode(f.read()).decode()

msg = {
    'thread_id': '<current-thread-id>',
    'session_id': '<session-id>',
    'response': 'Screenshot caption here',
    'timestamp': '2026-03-03T00:00:00Z',
    'attachments': [{'filename': 'screen.png', 'data': b64}]
}
payload = json.dumps(msg).encode()

def resp_bulk(s):
    return b'\$' + str(len(s)).encode() + b'\r\n' + s + b'\r\n'

cmd = b'*3\r\n' + resp_bulk(b'RPUSH') + resp_bulk(b'orchestrator:outbox') + resp_bulk(payload)
s = socket.socket()
s.connect(('redis', 6379))
s.sendall(cmd)
import time; time.sleep(1)
s.recv(1024)  # :1\r\n = success
s.close()
```

**Important:** The thread ID key in Redis is `ordis:thread:<session-id>`. Fetch it fresh before every send — each new Discord message creates a new thread mapping.

## Troubleshooting

| Symptom | Cause | Fix |
|---------|-------|-----|
| `Connection refused` on port 5555 | ADB not listening / firewall | Enable TCP ADB on emulator; add firewall rule |
| `Connection refused` on port 5554 | Console port blocked | Add Windows Firewall rule for 5554 |
| Screenshot is black (~10KB) | GPU rendering, use `screencap` | Use emulator console `screenrecord screenshot` instead |
| Screenshot is black after console method | Screen locked or ANR dialog | Wake screen (`KEYCODE_WAKEUP`), dismiss dialog |
| ANR dialog blocking screen | System UI not responding | Use `uiautomator dump` to find button coords, tap "Wait" |

### Dismissing ANR Dialogs

```bash
# Dump UI to find button positions
adb shell uiautomator dump /sdcard/ui.xml
adb shell cat /sdcard/ui.xml | grep -o 'text="[^"]*" [^>]*bounds="[^"]*"'

# Tap the "Wait" button (example coords for 1080x2340 screen)
adb shell input tap 540 1320
```
