PQVPN GUI (PySide6)

This repository contains a minimal PySide6 GUI to manage a local PQVPN node (main.py).

Features:
- Select a config file
- Start/Stop node (main.py) using the venv python if present
- Edit TUN settings in `plugins.tun` and save them
- Visualize discovered peers and sessions (parses node log)
- Graphical 2D view of peers (click nodes to initiate actions)
- Send HELLO and HS1 packets manually (for testing)
- Run a simple SOCKS test (curl) and show output

Quick start
1. Install requirements (preferably in the project's venv):

```bash
pip install -r requirements.txt
```

2. Start the GUI:

```bash
python gui.py
```

3. Use the GUI to pick `config.yaml`, start the node, and open the TUN settings.

Notes
- The GUI tails `/tmp/pqvpn_gui_node.log` by default; when you start the node from GUI, stdout/stderr are redirected to this file.
- To apply default-route changes automatically, set `plugins.tun.apply_routes: true` in the config (requires root or capabilities).
- The HELLO/HS1 buttons send minimal packets to the peer; for full handshake functionality use the node implementation.

Security
- Running GUI and node may require elevated privileges for TUN operations and route changes. Be careful with `setcap` or running Python as root.

