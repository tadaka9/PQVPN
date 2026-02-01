import os
import fcntl
import struct
import subprocess
import asyncio
import threading
import time
import select
from typing import List, Tuple, Optional

TUNSETIFF = 0x400454CA
IFF_TUN = 0x0001
IFF_NO_PI = 0x1000


class TunDevice:
    def __init__(self, name: str = "pqtun0"):
        self.name = name
        self.fd = None

    def open(self):
        """Open TUN device (requires root). Returns file descriptor."""
        self.fd = os.open("/dev/net/tun", os.O_RDWR | os.O_NONBLOCK)
        ifr = struct.pack("16sH", self.name.encode(), IFF_TUN | IFF_NO_PI)
        ifs = fcntl.ioctl(self.fd, TUNSETIFF, ifr)
        self.name = ifs[:16].strip(b"\x00").decode()
        return self.fd

    def read(self, n=4096):
        if self.fd:
            return os.read(self.fd, n)
        return b""

    def write(self, data: bytes):
        if self.fd:
            return os.write(self.fd, data)
        return 0

    def close(self):
        if self.fd:
            os.close(self.fd)
            self.fd = None

    # ----------------- new helpers -----------------
    def _run_cmd(
        self, cmd: List[str], check: bool = True, capture: bool = False
    ) -> Tuple[int, str]:
        """Run a command, using sudo if not running as root. Returns (returncode, output)."""
        prefix = []
        if os.geteuid() != 0:
            # prefer sudo so GUI can prompt for password if needed
            prefix = ["sudo"]
        final = prefix + cmd
        try:
            if capture:
                res = subprocess.run(
                    final,
                    check=check,
                    stdout=subprocess.PIPE,
                    stderr=subprocess.STDOUT,
                    text=True,
                )
                return res.returncode, res.stdout
            else:
                res = subprocess.run(final, check=check)
                return res.returncode, ""
        except subprocess.CalledProcessError as e:
            out = ""
            try:
                out = (
                    e.output.decode()
                    if isinstance(e.output, bytes)
                    else (e.output or "")
                )
            except Exception:
                out = str(e)
            return e.returncode if hasattr(e, "returncode") else 1, out
        except Exception as e:
            return 1, str(e)

    def generate_setup_commands(
        self,
        cidr: Optional[str] = None,
        up_cmd: Optional[str] = None,
        apply_routes: bool = False,
        route_via: Optional[str] = None,
        force_replace_default: bool = False,
    ) -> List[str]:
        """Return the list of shell commands that would be executed to configure the TUN.

        - If `up_cmd` is provided, it will be used as-is (single command string to run in shell).
        - Otherwise the default commands will be used: create tun device, `ip addr add <cidr> dev <if>` and `ip link set dev <if> up`.
        - If `apply_routes` is True and `route_via` is provided, add `ip route replace default via <route_via> dev <if>`.
          If `apply_routes` is True and no `route_via` is provided, previously the code replaced the default route via the TUN; now
          the default behavior is to NOT replace the system default route unless `route_via` is provided. Set `force_replace_default=True`
          to keep the old behavior.
        """
        cmds: List[str] = []
        # Ensure device exists via ip tuntap add (idempotent will fail if exists but that's tolerable)
        cmds.append(f"ip tuntap add dev {self.name} mode tun")
        if up_cmd:
            cmds.append(up_cmd)
        else:
            if cidr:
                cmds.append(f"ip addr add {cidr} dev {self.name}")
            cmds.append(f"ip link set dev {self.name} up")

        if apply_routes:
            if route_via:
                cmds.append(f"ip route replace default via {route_via} dev {self.name}")
            else:
                # default safe behavior: do not replace the system default route unless explicit route_via provided
                if force_replace_default:
                    cmds.append(f"ip route replace default dev {self.name}")
                else:
                    # add informational echo instead of modifying routes
                    cmds.append(
                        f"echo 'Skipping default route replace for {self.name}: no route_via provided (safe default).' && true"
                    )
        return cmds

    def setup(
        self,
        cidr: Optional[str] = None,
        up_cmd: Optional[str] = None,
        apply_routes: bool = False,
        route_via: Optional[str] = None,
        dry_run: bool = False,
        force_replace_default: bool = False,
    ) -> Tuple[bool, str]:
        """Create/configure the TUN device and optionally apply routes.

        Returns (success, message). If `dry_run` is True, commands are returned but not executed.
        """
        try:
            if self.fd is None:
                # open device (may require root)
                try:
                    self.open()
                except Exception as e:
                    return False, f"Failed to open /dev/net/tun: {e}"

            cmds = self.generate_setup_commands(
                cidr=cidr,
                up_cmd=up_cmd,
                apply_routes=apply_routes,
                route_via=route_via,
                force_replace_default=force_replace_default,
            )
            if dry_run:
                return True, "\n".join(cmds)

            out_lines = []
            for c in cmds:
                # If command is a shell string (up_cmd), run via shell so pipes/&& work
                if up_cmd and c == up_cmd:
                    # run via shell
                    rc, out = self._run_cmd(["sh", "-c", c], check=False, capture=True)
                else:
                    # simple split
                    parts = c.split()
                    rc, out = self._run_cmd(parts, check=False, capture=True)
                out_lines.append(f"cmd={c} rc={rc} out={out.strip()}")
                if rc != 0:
                    # stop on first failure and return diagnostic
                    return False, "\n".join(out_lines)
            return True, "\n".join(out_lines)
        except Exception as e:
            return False, str(e)

    def teardown(
        self,
        cidr: Optional[str] = None,
        remove_routes: bool = False,
        route_via: Optional[str] = None,
    ) -> Tuple[bool, str]:
        """Tear down the TUN device and optionally remove routes created by `setup`.

        If `cidr` is provided, remove that IP from the interface. If `remove_routes` is True, attempt to remove default route
        pointing at this interface (best-effort).
        """
        try:
            cmds: List[str] = []
            if cidr:
                cmds.append(f"ip addr del {cidr} dev {self.name}")
            if remove_routes:
                if route_via:
                    cmds.append(f"ip route del default via {route_via} dev {self.name}")
                else:
                    # Best-effort: delete default route that references the device
                    cmds.append(f"ip route del default dev {self.name}")
            # attempt to bring interface down
            cmds.append(f"ip link set dev {self.name} down")
            # delete the TUN device
            cmds.append(f"ip link delete dev {self.name}")

            out_lines = []
            for c in cmds:
                parts = c.split()
                rc, out = self._run_cmd(parts, check=False, capture=True)
                out_lines.append(f"cmd={c} rc={rc} out={out.strip()}")
            # close fd if open
            try:
                self.close()
            except Exception:
                pass
            return True, "\n".join(out_lines)
        except Exception as e:
            return False, str(e)


class TunAdapter:
    """Adapter glue between PQNode and the TunDevice.

    Usage:
      adapter = TunAdapter(cfg_dict)
      await adapter.start(node)

    Config keys expected in cfg_dict:
      - device: interface name (e.g. pqvpn0)
      - cidr: IP/mask assigned to TUN (e.g. 10.10.10.2/24)
      - up_cmd: optional shell command to configure/up interface
      - apply_routes: bool, whether to replace default route via this TUN
      - route_via: optional gateway IP to use when applying default route
    """

    def __init__(self, cfg: dict | None = None):
        self.cfg = cfg or {}
        name = self.cfg.get("device") or self.cfg.get("dev") or "pqtun0"
        self.dev = TunDevice(name=name)
        self._read_thread = None
        self._stop = False
        self.circuit_id = 1  # Fixed circuit ID for TUN packets

    async def start(self, node):
        """Open TUN, configure it according to config and start background read loop.
        node: PQNode instance which must implement an async method handle_tun_packet(bytes).
        """
        # Configure interface
        cidr = self.cfg.get("cidr") or self.cfg.get("address") or self.cfg.get("ip")
        up_cmd = self.cfg.get("up_cmd") or self.cfg.get("upcmd")
        apply_routes = bool(self.cfg.get("apply_routes", False))
        route_via = self.cfg.get("route_via")

        # If running as non-root, try to run the ip commands via sudo rather than ioctl
        if os.geteuid() != 0:
            # If the environment explicitly allows automatic sudo-based TUN creation,
            # continue with the existing behavior. Otherwise avoid invoking sudo
            # (which may prompt for a password and block the process) and instead
            # write a small helper script the user can run as root.
            if not os.environ.get("PQVPN_ALLOW_SUDO_TUN"):
                try:
                    cmds = self.dev.generate_setup_commands(
                        cidr=cidr,
                        up_cmd=up_cmd,
                        apply_routes=apply_routes,
                        route_via=route_via,
                        force_replace_default=bool(
                            self.cfg.get("force_replace_default", False)
                        ),
                    )
                    script_path = "/tmp/pqvpn_setup_tun.sh"
                    with open(script_path, "w") as sf:
                        sf.write("#!/bin/sh\n")
                        for cmd_line in cmds:
                            sf.write(cmd_line + "\n")
                    try:
                        os.chmod(script_path, 0o750)
                    except Exception:
                        pass
                    print(
                        f"[TUN_ADAPTER] Running as non-root and automatic sudo not allowed. Wrote helper script to {script_path}."
                    )
                    print(
                        f"[TUN_ADAPTER] To create the TUN and apply routes, run as root: sudo {script_path}"
                    )
                except Exception as e:
                    print(f"[TUN_ADAPTER] Could not write helper script: {e}")
                # Do not attempt to run sudo here to avoid blocking; return so node can continue without TUN
                return
            # If we're here, PQVPN_ALLOW_SUDO_TUN is set and we should attempt to run the commands with sudo
            force_replace = bool(self.cfg.get("force_replace_default", False))
            cmds = self.dev.generate_setup_commands(
                cidr=cidr,
                up_cmd=up_cmd,
                apply_routes=apply_routes,
                route_via=route_via,
                force_replace_default=force_replace,
            )
            out_lines = []
            for c in cmds:
                try:
                    if up_cmd and c == up_cmd:
                        rc, out = self.dev._run_cmd(
                            ["sh", "-c", c], check=False, capture=True
                        )
                    else:
                        parts = c.split()
                        rc, out = self.dev._run_cmd(parts, check=False, capture=True)
                except Exception as e:
                    rc, out = 1, str(e)
                out_lines.append(f"cmd={c} rc={rc} out={out.strip()}")
                # tolerate "exists" errors (idempotent)
                if rc != 0:
                    low = (out or "").lower()
                    if (
                        "exist" in low
                        or "file exists" in low
                        or "already exists" in low
                    ):
                        # ignore and continue
                        continue
                    # instead of aborting immediately, write a helper script the user can run as root
                    try:
                        script_path = "/tmp/pqvpn_setup_tun.sh"
                        with open(script_path, "w") as sf:
                            sf.write("#!/bin/sh\n")
                            for cmd_line in cmds:
                                sf.write("sudo " + cmd_line + "\n")
                        try:
                            os.chmod(script_path, 0o750)
                        except Exception:
                            pass
                        print(f"[TUN_ADAPTER] command failed: {c}\n{out}")
                        print(
                            f"[TUN_ADAPTER] Wrote helper script to {script_path}. Run it as root to create the TUN and apply routes:"
                        )
                        print(f"  sudo {script_path}")
                        print("[TUN_ADAPTER] Aborting TUN setup for now.")
                    except Exception as e2:
                        print(f"[TUN_ADAPTER] Failed to write helper script: {e2}")
                        print(
                            "[TUN_ADAPTER] Aborting TUN setup; re-run GUI/node as root or create interface manually using the printed commands"
                        )
                        print("\n".join(out_lines))
                    return
            print("[TUN_ADAPTER] sudo commands executed:\n" + "\n".join(out_lines))
            # attempt to open the device now that it exists
            try:
                self.dev.open()
            except Exception as e:
                print(
                    f"[TUN_ADAPTER] Warning: could not open /dev/net/tun after creating interface: {e}"
                )
                print(
                    "You may need to run the node as root or give the process CAP_NET_ADMIN to access the tun device."
                )
                print("Generated commands to run as root (or copy/paste):")
                for l in cmds:
                    print("  ", l)
                return
        else:
            # Running as root - open and run setup (setup will open if needed)
            try:
                # open device and apply setup
                if self.dev.fd is None:
                    try:
                        self.dev.open()
                    except Exception as e:
                        print(f"[TUN_ADAPTER] open() failed even as root: {e}")
                if self.dev.fd is None:
                    print("[TUN_ADAPTER] TUN device not opened, skipping read loop")
                    return
                force_replace = bool(self.cfg.get("force_replace_default", False))
                success, msg = self.dev.setup(
                    cidr=cidr,
                    up_cmd=up_cmd,
                    apply_routes=apply_routes,
                    route_via=route_via,
                    dry_run=False,
                    force_replace_default=force_replace,
                )
                if not success:
                    print(f"[TUN_ADAPTER] TUN setup failed: {msg}")
                else:
                    print(f"[TUN_ADAPTER] TUN setup success:\n{msg}")
            except Exception as e:
                print(f"[TUN_ADAPTER] Setup error: {e}")
                return

        # start read loop in a thread because reading from tun fd is blocking
        def read_loop():
            while not self._stop:
                try:
                    ready, _, _ = select.select([self.dev.fd], [], [], 1.0)
                    if ready:
                        data = self.dev.read(65535)
                        if data:
                            # schedule coroutine to handle packet
                            try:
                                asyncio.run_coroutine_threadsafe(
                                    node.handle_tun_packet(data),
                                    getattr(node, "_loop", asyncio.get_event_loop()),
                                )
                            except Exception:
                                # fallback: call create_task if loop is same
                                try:
                                    loop = asyncio.get_event_loop()
                                    loop.create_task(node.handle_tun_packet(data))
                                except Exception:
                                    pass
                except Exception as e:
                    # avoid noisy output for EAGAIN, but print other failures
                    if "Resource temporarily unavailable" not in str(e):
                        print(f"[TUN_ADAPTER] read error: {e}")
                        time.sleep(0.5)

        self._stop = False
        self._read_thread = threading.Thread(target=read_loop, daemon=True)
        self._read_thread.start()

    async def write(self, packet: bytes):
        """Write an IP packet (bytes) into the TUN device."""
        try:
            self.dev.write(packet)
        except Exception as e:
            print(f"[TUN_ADAPTER] write error: {e}")

    async def stop(self):
        self._stop = True
        try:
            if self._read_thread:
                self._read_thread.join(timeout=1.0)
        except Exception:
            pass
        # teardown network settings if configured
        cidr = self.cfg.get("cidr") or self.cfg.get("address") or self.cfg.get("ip")
        remove_routes = bool(self.cfg.get("remove_routes", False))
        route_via = self.cfg.get("route_via")
        try:
            ok, msg = self.dev.teardown(
                cidr=cidr, remove_routes=remove_routes, route_via=route_via
            )
            if not ok:
                print(f"[TUN_ADAPTER] teardown returned: {msg}")
            else:
                print(f"[TUN_ADAPTER] teardown success: {msg}")
        except Exception as e:
            print(f"[TUN_ADAPTER] teardown error: {e}")
        try:
            self.dev.close()
        except Exception:
            pass
