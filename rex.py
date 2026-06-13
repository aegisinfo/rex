#!/usr/bin/env python3
# ============================================================
# ÆGIS Security Audit — rex.py
# Cross-platform: Windows · macOS · Linux
# ============================================================

import sys
import os
import subprocess
import platform
import socket
import psutil
import json
import datetime
import shlex
import shutil
import urllib.request
import urllib.error
import threading
import math
import random
import stat
import re
from concurrent.futures import ThreadPoolExecutor, as_completed

try:
    from PyQt6.QtWidgets import (
        QApplication, QMainWindow, QWidget, QVBoxLayout, QHBoxLayout,
        QPushButton, QLabel, QTextEdit, QScrollArea, QFrame, QSplitter,
        QListWidget, QListWidgetItem, QProgressBar, QFileDialog, QSizePolicy,
        QDialog, QLineEdit
    )
    from PyQt6.QtCore import Qt, QThread, pyqtSignal, QTimer, QRect
    from PyQt6.QtGui import QPainter, QPen, QColor, QFont, QFontDatabase, QPalette
except ImportError:
    print("PyQt6 not installed.\nRun: pip install PyQt6 psutil")
    sys.exit(1)

# ============================================================
# PLATFORM DETECTION
# ============================================================
_OS      = platform.system()
IS_WIN   = _OS == "Windows"
IS_MAC   = _OS == "Darwin"
IS_LINUX = _OS == "Linux"

# ============================================================
# KONFIGURATION
# ============================================================
VERSION  = "1.3.0"
APP_NAME = "ÆGIS Security Audit"

COLORS = {
    "bg":        "#07070f",
    "bg2":       "#0d0d1a",
    "bg3":       "#12121f",
    "border":    "#1a1a2e",
    "cyan":      "#00e5c0",
    "cyan_dim":  "#00b89a",
    "text":      "#e0e0f0",
    "text2":     "#9090b0",
    "text3":     "#505070",
    "green":     "#39ff14",
    "red":       "#ff4444",
    "orange":    "#ffaa00",
    "white":     "#ffffff",
}

AUDIT_SECTIONS = [
    "System Info",
    "CPU & Memory",
    "Disk",
    "Network",
    "Open Ports",
    "Running Processes",
    "Startup Services",
    "Firewall",
    "Users & Groups",
    "Sudo / Privileges",
    "SSH Config",
    "Scheduled Tasks",
    "SUID/SGID Files",
    "World-Writable Files",
    "Environment Secrets",
    "Sensitive File Permissions",
]

VIRUS_SECTION = "Virus Scan (ClamAV)"
SECTIONS = AUDIT_SECTIONS + [VIRUS_SECTION]

# ============================================================
# LATTICE BAKGRUND (diamond lattice — upgraded)
# ============================================================
class LatticeWidget(QWidget):
    """Diamond lattice with breathing lines, traveling spark particles,
    and drifting intersection nodes."""

    _SPACING = 40

    def __init__(self, parent=None):
        super().__init__(parent)
        self._offset = 0.0
        self._frame  = 0
        # sparks: [progress 0→1, line_index, direction +1/-1]
        self._sparks: list = []
        self._timer  = QTimer(self)
        self._timer.timeout.connect(self._tick)
        self._timer.start(33)  # ~30 FPS

    def _tick(self):
        s = self._SPACING
        self._offset = (self._offset + 0.9) % s
        self._frame += 1
        # Spawn a new spark roughly every 55 frames (max 5 simultaneous)
        if self._frame % 55 == 0 and len(self._sparks) < 5:
            w = max(self.width(), 1)
            h = max(self.height(), 1)
            n_lines = (w + h * 2) // s + 4
            self._sparks.append([0.0, random.randint(0, n_lines - 1),
                                  random.choice([-1, 1])])
        # Advance sparks; cull finished ones
        self._sparks = [[p + 0.011, i, d] for p, i, d in self._sparks if p < 1.0]
        self.update()

    def paintEvent(self, event):
        super().paintEvent(event)
        p = QPainter(self)
        p.setRenderHint(QPainter.RenderHint.Antialiasing)
        w, h  = self.width(), self.height()
        s     = self._SPACING
        off   = self._offset
        frame = self._frame

        origins = list(range(-w - int(h * 1.5), w + int(h * 1.5), s))

        # ── Per-line breathing alpha (sine wave, each line offset) ───────────
        for idx, i in enumerate(origins):
            a1 = max(2, int(5 + 5 * math.sin(frame * 0.018 + idx * 0.45)))
            a2 = max(2, int(5 + 5 * math.sin(frame * 0.018 + idx * 0.45 + 1.1)))
            p.setPen(QPen(QColor(0, 229, 192, a1), 1))
            p.drawLine(int(i + off), 0, int(i + h + off), h)
            p.setPen(QPen(QColor(0, 229, 192, a2), 1))
            p.drawLine(int(i - off), h, int(i + h - off), 0)

        # ── Drifting intersection nodes ──────────────────────────────────────
        dot_off = int(off) % s
        p.setPen(Qt.PenStyle.NoPen)
        for nx in range(-s + dot_off, w + s, s):
            for ny in range(-s + dot_off, h + s, s):
                p.setBrush(QColor(0, 229, 192, 20))
                p.drawEllipse(nx - 1, ny - 1, 3, 3)

        # ── Traveling spark particles ────────────────────────────────────────
        for progress, line_idx, direction in self._sparks:
            if line_idx >= len(origins):
                continue
            i  = origins[line_idx]
            t  = progress
            if direction == 1:   # \ direction
                sx, sy = int(i + off + t * h), int(t * h)
            else:                # / direction
                sx, sy = int(i + h - off - t * h), int(t * h)
            if not (0 <= sx <= w and 0 <= sy <= h):
                continue
            # Layered glow: outer halo → bright core
            for radius, alpha in ((10, 6), (5, 25), (2, 110), (1, 220)):
                p.setPen(Qt.PenStyle.NoPen)
                p.setBrush(QColor(0, 229, 192, alpha))
                p.drawEllipse(sx - radius, sy - radius, radius * 2, radius * 2)

        p.end()


# ============================================================
# AUDIT WORKER (bakgrundstråd)
# ============================================================
class AuditWorker(QThread):
    section_done  = pyqtSignal(str, str, str)
    scan_progress = pyqtSignal(str, int)
    all_done      = pyqtSignal()

    def __init__(self, sections, scan_path=None):
        super().__init__()
        self.sections = sections
        if scan_path is None:
            scan_path = os.path.expanduser("~")
        self.scan_path = os.path.realpath(scan_path)
        self._stop = False

    def stop(self):
        self._stop = True

    def _run_safe(self, section):
        try:
            return self._run_section(section)
        except Exception as e:
            return "error", str(e)

    def run(self):
        max_workers = min(8, len(self.sections))
        with ThreadPoolExecutor(max_workers=max_workers) as ex:
            futures = {ex.submit(self._run_safe, s): s
                       for s in self.sections if not self._stop}
            for future in as_completed(futures):
                if self._stop:
                    break
                section = futures[future]
                try:
                    status, output = future.result()
                except Exception as e:
                    status, output = "error", str(e)
                self.section_done.emit(section, status, output)
        self.all_done.emit()

    # ── helpers ──────────────────────────────────────────────
    @staticmethod
    def _cmd(args, timeout=10):
        """Safe command runner — no shell=True."""
        if isinstance(args, str):
            args = shlex.split(args)
        try:
            r = subprocess.run(
                args,
                shell=False,
                capture_output=True,
                text=True,
                timeout=timeout,
            )
            return (r.stdout + r.stderr).strip()
        except FileNotFoundError:
            return "[not found]"
        except subprocess.TimeoutExpired:
            return "[timeout]"
        except Exception as e:
            return f"[error: {e}]"

    @staticmethod
    def _na(feature):
        return "ok", f"[N/A on {_OS}] {feature} is not applicable on this platform."

    # ── section dispatcher ────────────────────────────────────
    def _run_section(self, section):
        cmd = self._cmd

        # ── System Info (all platforms) ───────────────────────
        if section == "System Info":
            lines = [
                f"Hostname   : {socket.gethostname()}",
                f"OS         : {platform.platform()}",
                f"Kernel     : {platform.release()}",
                f"Arch       : {platform.machine()}",
                f"Python     : {platform.python_version()}",
                f"User       : {os.getenv('USERNAME') or os.getenv('USER', 'unknown')}",
                f"Date/Time  : {datetime.datetime.now().strftime('%Y-%m-%d %H:%M:%S')}",
            ]
            return "ok", "\n".join(lines)

        # ── CPU & Memory (all platforms via psutil) ───────────
        elif section == "CPU & Memory":
            cpu_pct = psutil.cpu_percent(interval=1)
            cpu_cnt = psutil.cpu_count(logical=True)
            mem     = psutil.virtual_memory()
            swap    = psutil.swap_memory()
            lines = [
                f"CPU Usage  : {cpu_pct}%",
                f"CPU Cores  : {cpu_cnt}",
                f"RAM Total  : {mem.total  // (1024**2)} MB",
                f"RAM Used   : {mem.used   // (1024**2)} MB ({mem.percent}%)",
                f"RAM Free   : {mem.available // (1024**2)} MB",
                f"Swap Total : {swap.total // (1024**2)} MB",
                f"Swap Used  : {swap.used  // (1024**2)} MB ({swap.percent}%)",
            ]
            status = "warn" if mem.percent > 85 or swap.percent > 50 else "ok"
            return status, "\n".join(lines)

        # ── Disk (all platforms via psutil) ───────────────────
        elif section == "Disk":
            out = []
            warn = False
            for part in psutil.disk_partitions():
                try:
                    usage = psutil.disk_usage(part.mountpoint)
                    pct = usage.percent
                    out.append(
                        f"{part.device} → {part.mountpoint}  "
                        f"{usage.used // (1024**3)}G / {usage.total // (1024**3)}G ({pct}%)"
                    )
                    if pct > 90:
                        warn = True
                except Exception:
                    pass
            return ("warn" if warn else "ok"), "\n".join(out) or "No partitions found"

        # ── Network (all platforms via psutil) ────────────────
        elif section == "Network":
            addrs = psutil.net_if_addrs()
            stats = psutil.net_if_stats()
            out = []
            for iface, addr_list in addrs.items():
                st = stats.get(iface)
                up = "UP" if st and st.isup else "DOWN"
                for a in addr_list:
                    if a.family == socket.AF_INET:
                        out.append(f"{iface} [{up}]  {a.address}")
            return "ok", "\n".join(out) or "No network interfaces"

        # ── Open Ports ────────────────────────────────────────
        elif section == "Open Ports":
            suspicious = ["4444", "1337", "31337", "6666", "9999"]
            if IS_WIN:
                out = cmd(["netstat", "-ano"], timeout=10)
            elif IS_MAC:
                out = cmd(["netstat", "-an", "-p", "tcp"], timeout=10)
                if not out or "[not found]" in out:
                    out = cmd(["lsof", "-iTCP", "-sTCP:LISTEN", "-n", "-P"], timeout=10)
            else:  # Linux
                out = cmd(["ss", "-tlnp"], timeout=8)
                if not out or "[not found]" in out:
                    out = cmd(["netstat", "-tlnp"], timeout=8)
            status = "warn" if any(p in out for p in suspicious) else "ok"
            return status, out or "No open ports found"

        # ── Running Processes (psutil — all platforms) ────────
        elif section == "Running Processes":
            procs = []
            for p in psutil.process_iter(["pid", "name", "username", "cpu_percent"]):
                try:
                    procs.append(
                        f"{p.info['pid']:>6}  {str(p.info['username'] or ''):<15}  {p.info['name']}"
                    )
                except Exception:
                    pass
            suffix = "\n[truncated...]" if len(procs) > 60 else ""
            return "ok", "\n".join(procs[:60]) + suffix

        # ── Startup Services ──────────────────────────────────
        elif section == "Startup Services":
            if IS_WIN:
                out = cmd(
                    ["sc", "query", "type=", "all", "state=", "running"],
                    timeout=12,
                )
                if not out or "[not found]" in out:
                    out = cmd(
                        ["powershell", "-NoProfile", "-Command",
                         "Get-Service | Where-Object {$_.StartType -eq 'Automatic'} | "
                         "Select-Object Name,Status | Format-Table -AutoSize"],
                        timeout=15,
                    )
            elif IS_MAC:
                out = cmd(["launchctl", "list"], timeout=10)
                if out:
                    out = "\n".join(out.splitlines()[:50])
            else:
                out = cmd(
                    ["systemctl", "list-unit-files", "--type=service", "--state=enabled"],
                    timeout=10,
                )
                if out:
                    out = "\n".join(out.splitlines()[:40])
            return "ok", out or "Could not retrieve startup services"

        # ── Firewall ──────────────────────────────────────────
        elif section == "Firewall":
            if IS_WIN:
                out = cmd(
                    ["netsh", "advfirewall", "show", "allprofiles"],
                    timeout=10,
                )
                status = "ok"
                if "State                                 OFF" in out:
                    status = "warn"
                return status, out or "Could not query Windows Firewall"

            elif IS_MAC:
                # Application-level firewall (socketfilterfw)
                fw_bin = "/usr/libexec/ApplicationFirewall/socketfilterfw"
                if os.path.exists(fw_bin):
                    state  = cmd([fw_bin, "--getglobalstate"], timeout=6)
                    blocks = cmd([fw_bin, "--getblockall"],    timeout=6)
                    stealth = cmd([fw_bin, "--getstealthmode"], timeout=6)
                    out = "\n".join([
                        f"Global state : {state}",
                        f"Block all    : {blocks}",
                        f"Stealth mode : {stealth}",
                    ])
                    status = "warn" if "disabled" in state.lower() else "ok"
                    return status, out
                # Fallback: pf
                out = cmd(["pfctl", "-s", "rules"], timeout=8)
                return "ok", out or "pf rules empty or permission denied"

            else:  # Linux
                ufw = cmd(["ufw", "status", "verbose"], timeout=8)
                if "inactive" in ufw.lower() or not ufw or "[not found]" in ufw or "[error" in ufw:
                    iptables = cmd(["iptables", "-L", "-n", "--line-numbers"], timeout=8)
                    if iptables:
                        iptables = "\n".join(iptables.splitlines()[:30])
                    status = "warn" if ufw and "inactive" in ufw.lower() else "ok"
                    return status, (ufw + "\n\niptables:\n" + iptables).strip()
                return "ok", ufw

        # ── Users & Groups ────────────────────────────────────
        elif section == "Users & Groups":
            if IS_WIN:
                out = cmd(["net", "user"], timeout=8)
                return "ok", out or "Could not list users"

            elif IS_MAC:
                out = cmd(["dscl", ".", "-list", "/Users"], timeout=8)
                if out and "[not found]" not in out:
                    # filter hidden system users (start with _)
                    filtered = [l for l in out.splitlines() if not l.startswith("_")]
                    return "ok", "\n".join(filtered)
                # fallback
                try:
                    lines = []
                    with open("/etc/passwd") as f:
                        for line in f:
                            parts = line.strip().split(":")
                            if len(parts) >= 7 and parts[6] not in ("/usr/bin/false", "/sbin/nologin"):
                                lines.append(f"{parts[0]:<20} uid={parts[2]:<6} home={parts[5]}")
                    return "ok", "\n".join(lines) or "No login users found"
                except Exception as e:
                    return "error", str(e)

            else:  # Linux
                try:
                    lines = []
                    with open("/etc/passwd") as f:
                        for line in f:
                            parts = line.strip().split(":")
                            if len(parts) >= 7 and parts[6] not in (
                                "/usr/sbin/nologin", "/bin/false", "/sbin/nologin"
                            ):
                                lines.append(f"{parts[0]:<20} uid={parts[2]:<6} home={parts[5]}")
                    return "ok", "\n".join(lines) or "No login users found"
                except Exception as e:
                    return "error", f"Could not read /etc/passwd: {e}"

        # ── Sudo / Privileges ─────────────────────────────────
        elif section == "Sudo / Privileges":
            if IS_WIN:
                # Show token privileges and whether we're in an elevated context
                out = cmd(["whoami", "/all"], timeout=8)
                if not out or "[not found]" in out:
                    out = cmd(["whoami", "/priv"], timeout=8)
                status = "warn" if "SeDebugPrivilege" in out or "Enabled" in out else "ok"
                return status, out or "Could not query privileges"

            else:  # Linux + macOS
                out = cmd(["sudo", "-l"], timeout=8)
                if not out or "[error" in out or "[not found]" in out:
                    return "warn", "Could not retrieve sudo rules (sudo -l failed)"
                status = "warn" if "NOPASSWD" in out else "ok"
                return status, out

        # ── SSH Config ────────────────────────────────────────
        elif section == "SSH Config":
            if IS_WIN:
                paths = [
                    r"C:\ProgramData\ssh\sshd_config",
                    os.path.expandvars(r"%WINDIR%\System32\OpenSSH\sshd_config"),
                ]
            else:
                paths = ["/etc/ssh/sshd_config"]

            cfg_path = next((p for p in paths if os.path.exists(p)), None)
            if cfg_path is None:
                return "ok", "sshd_config not found — SSH server may not be installed"
            try:
                with open(cfg_path) as f:
                    raw = f.read()
                active = [l for l in raw.splitlines() if l.strip() and not l.strip().startswith("#")]
                out = "\n".join(active)
            except PermissionError:
                return "warn", "Permission denied reading sshd_config (run as admin/root for full audit)"
            except Exception as e:
                return "error", str(e)

            warnings = []
            if "PermitRootLogin yes" in out:
                warnings.append("⚠  PermitRootLogin yes")
            if "PasswordAuthentication yes" in out:
                warnings.append("⚠  PasswordAuthentication yes")
            if "PermitEmptyPasswords yes" in out:
                warnings.append("⚠  PermitEmptyPasswords yes")
            status = "warn" if warnings else "ok"
            header = "\n".join(warnings) + "\n\n" if warnings else ""
            return status, (header + out).strip() or "SSH config empty"

        # ── Scheduled Tasks / Cron ────────────────────────────
        elif section == "Scheduled Tasks":
            if IS_WIN:
                out = cmd(["schtasks", "/query", "/fo", "LIST", "/v"], timeout=15)
                if out:
                    # Trim to first 60 lines to avoid wall of text
                    out = "\n".join(out.splitlines()[:60])
                    if len(out.splitlines()) == 60:
                        out += "\n[truncated...]"
                return "ok", out or "No scheduled tasks found"

            elif IS_MAC:
                parts = []
                user_cron = cmd(["crontab", "-l"], timeout=5)
                if user_cron and "[error" not in user_cron and "[not found]" not in user_cron:
                    parts.append("=== User crontab ===\n" + user_cron)
                # LaunchAgents
                for d in [
                    os.path.expanduser("~/Library/LaunchAgents"),
                    "/Library/LaunchAgents",
                    "/Library/LaunchDaemons",
                ]:
                    if os.path.isdir(d):
                        files = os.listdir(d)
                        if files:
                            parts.append(f"=== {d} ===\n" + "\n".join(files))
                return "ok", "\n\n".join(parts) or "No scheduled tasks found"

            else:  # Linux
                parts = []
                user_cron = cmd(["crontab", "-l"], timeout=5)
                if user_cron and "[error" not in user_cron and "[not found]" not in user_cron:
                    parts.append("=== User crontab ===\n" + user_cron)
                cron_d = cmd(["ls", "/etc/cron.d"], timeout=5)
                if cron_d and "[error" not in cron_d:
                    parts.append("=== /etc/cron.d ===\n" + cron_d)
                try:
                    with open("/etc/crontab") as f:
                        active = [l for l in f.read().splitlines() if l.strip() and not l.startswith("#")]
                    if active:
                        parts.append("=== /etc/crontab ===\n" + "\n".join(active))
                except Exception:
                    pass
                return "ok", "\n\n".join(parts) or "No cron jobs found"

        # ── SUID/SGID Files ───────────────────────────────────
        elif section == "SUID/SGID Files":
            if IS_WIN:
                # Windows equivalent: files with Everyone:FullControl
                out = cmd(
                    ["powershell", "-NoProfile", "-Command",
                     r"Get-ChildItem 'C:\Windows\System32' -File | "
                     r"ForEach-Object { $acl = Get-Acl $_.FullName; "
                     r"$acl.Access | Where-Object {$_.IdentityReference -match 'Everyone' "
                     r"-and $_.FileSystemRights -match 'FullControl'} | "
                     r"ForEach-Object { $_.Path } } | Select-Object -First 30"],
                    timeout=30,
                )
                status = "warn" if out and "[error" not in out and out.strip() else "ok"
                return status, out or "No world-accessible binaries found in System32"

            else:  # Linux + macOS
                safe_paths = ["/usr", "/bin", "/sbin", "/lib", "/lib64", "/opt"]
                if IS_MAC:
                    safe_paths = ["/usr", "/bin", "/sbin", "/opt"]
                existing = [p for p in safe_paths if os.path.isdir(p)]
                out = cmd(["find"] + existing + ["-perm", "/6000", "-type", "f"], timeout=20)
                if out:
                    lines = out.splitlines()[:30]
                    out = "\n".join(lines)
                    if len(lines) == 30:
                        out += "\n[truncated at 30 results]"
                status = "warn" if out and "[error" not in out else "ok"
                return status, out or "No SUID/SGID files found in system dirs"

        # ── World-Writable Files ──────────────────────────────
        elif section == "World-Writable Files":
            if IS_WIN:
                # Check world-writable dirs in common system paths
                out = cmd(
                    ["icacls", r"C:\Windows\Temp"],
                    timeout=10,
                )
                return "ok", out or "Could not check world-writable paths"

            else:  # Linux + macOS
                check_paths = ["/etc", "/usr", "/bin", "/sbin"]
                if IS_MAC:
                    check_paths = ["/etc", "/usr", "/bin"]
                out = cmd(
                    ["find"] + check_paths + ["-perm", "-o+w", "-type", "f"],
                    timeout=15,
                )
                if out:
                    lines = out.splitlines()[:20]
                    out = "\n".join(lines)
                status = "warn" if out and "[error" not in out and "[timeout]" not in out else "ok"
                return status, out or "No world-writable files found in critical dirs"

        # ── Virus Scan (ClamAV) ───────────────────────────────
        elif section == "Virus Scan (ClamAV)":
            scan_path = os.path.realpath(self.scan_path)
            if not os.path.exists(scan_path):
                return "error", f"Scan path does not exist: {scan_path}"
            if not os.access(scan_path, os.R_OK):
                return "error", f"No read permission for: {scan_path}"

            clamscan = shutil.which("clamscan")
            if IS_WIN and not clamscan:
                # Try common Windows install path
                win_path = r"C:\Program Files\ClamAV\clamscan.exe"
                if os.path.exists(win_path):
                    clamscan = win_path

            if not clamscan:
                if IS_WIN:
                    install_hint = "winget install ClamAV  or  choco install clamav"
                elif IS_MAC:
                    install_hint = "brew install clamav && sudo freshclam"
                else:
                    install_hint = "sudo apt install clamav && sudo freshclam"
                return "warn", f"ClamAV not installed.\nInstall: {install_hint}"

            files_scanned = 0
            threats = []
            last_file = ""
            try:
                proc = subprocess.Popen(
                    [
                        clamscan,
                        "--recursive",
                        "--stdout",
                        "--no-summary",
                        "--max-filesize=100M",
                        "--max-scansize=500M",
                        scan_path,
                    ],
                    stdout=subprocess.PIPE,
                    stderr=subprocess.DEVNULL,
                    text=True,
                    bufsize=1,
                )
                for line in proc.stdout:
                    line = line.strip()
                    if not line:
                        continue
                    if "FOUND" in line:
                        threats.append(line)
                    # every non-empty line is a scanned file path
                    files_scanned += 1
                    last_file = line.split(":")[0]
                    short = last_file[-40:] if len(last_file) > 40 else last_file
                    self.scan_progress.emit(
                        f"Scanning {files_scanned} files… {short}", files_scanned
                    )
                proc.wait()
                if threats:
                    summary = f"⚠  {len(threats)} THREAT(S) FOUND\n\n" + "\n".join(threats)
                    return "critical", summary
                return "ok", f"✓ Clean — {files_scanned} files scanned\nPath: {scan_path}"
            except Exception as e:
                return "error", str(e)

        # ── Environment Secrets ───────────────────────────────
        elif section == "Environment Secrets":
            SECRET_NAME = re.compile(
                r"(key|token|secret|password|passwd|pwd|credential|auth|"
                r"apikey|api_key|access_key|private|bearer|jwt|oauth|webhook)",
                re.IGNORECASE,
            )
            SECRET_VAL = re.compile(
                r"^[A-Za-z0-9+/]{32,}$"          # base64-like long string
                r"|^[a-f0-9]{32,}$"               # hex hash
                r"|^sk-[A-Za-z0-9]{20,}"          # OpenAI-style
                r"|^ghp_|^ghs_|^github_pat_"      # GitHub tokens
                r"|^xox[bpoas]-",                  # Slack tokens
                re.IGNORECASE,
            )
            suspicious, clean = [], []
            for k, v in os.environ.items():
                if SECRET_NAME.search(k) or (v and SECRET_VAL.search(v)):
                    masked = (v[:4] + "****" + v[-2:]) if len(v) > 6 else "****"
                    suspicious.append(f"⚠  {k} = {masked}")
                else:
                    clean.append(k)
            out_parts = []
            if suspicious:
                out_parts.append(
                    f"=== Potential secrets ({len(suspicious)}) ===\n"
                    + "\n".join(suspicious[:40])
                    + ("\n[truncated…]" if len(suspicious) > 40 else "")
                )
            out_parts.append(
                f"=== Clean variables ({len(clean)}) ===\n"
                + ("None detected." if not clean else f"{len(clean)} variables — no suspicious names or values.")
            )
            return ("warn" if suspicious else "ok"), "\n\n".join(out_parts)

        # ── Sensitive File Permissions ────────────────────────
        elif section == "Sensitive File Permissions":
            if IS_WIN:
                return "ok", "[N/A on Windows] Unix file-mode checks not applicable."
            HOME = os.path.expanduser("~")
            checks = [
                (os.path.join(HOME, ".ssh"),                    0o700, "~/.ssh/"),
                (os.path.join(HOME, ".ssh", "id_rsa"),          0o600, "~/.ssh/id_rsa"),
                (os.path.join(HOME, ".ssh", "id_ed25519"),      0o600, "~/.ssh/id_ed25519"),
                (os.path.join(HOME, ".ssh", "authorized_keys"), 0o600, "~/.ssh/authorized_keys"),
                (os.path.join(HOME, ".ssh", "config"),          0o600, "~/.ssh/config"),
                (os.path.join(HOME, ".gnupg"),                  0o700, "~/.gnupg/"),
                (os.path.join(HOME, ".aws", "credentials"),     0o600, "~/.aws/credentials"),
                (os.path.join(HOME, ".netrc"),                  0o600, "~/.netrc"),
            ]
            # Scan home dir (depth ≤ 2) for .env / credentials files
            for root, dirs, files in os.walk(HOME):
                depth = root[len(HOME):].count(os.sep)
                if depth > 2:
                    dirs[:] = []
                    continue
                for fname in files:
                    if fname in (".env", ".env.local", ".env.production",
                                 "credentials.json", "secrets.json", ".envrc"):
                        checks.append((os.path.join(root, fname), 0o600, fname))
            issues, ok_items = [], []
            for path, required, label in checks:
                if not os.path.exists(path):
                    continue
                try:
                    mode = stat.S_IMODE(os.stat(path).st_mode)
                    if mode & ~required:
                        issues.append(
                            f"⚠  {label}: {oct(mode)} (should be ≤ {oct(required)})"
                        )
                    else:
                        ok_items.append(f"✓  {label}: {oct(mode)}")
                except Exception as e:
                    issues.append(f"?  {label}: {e}")
            out = ("\n".join(issues) + "\n\n" if issues else "") + "\n".join(ok_items)
            return ("warn" if issues else "ok"), out.strip() or "No sensitive files found"

        return "ok", "Section not implemented"


# ============================================================
# OLLAMA REMEDIATION
# ============================================================
REMEDIATION_PROMPT = """You are a {os} security hardening expert. A security audit found this issue:

Section: {section}
Finding:
{finding}

Output ONLY the exact shell commands needed to fix this specific finding. Follow these rules strictly:
- Raw commands only — no explanation, no markdown, no code fences, no backticks, no bullets, no numbers
- One command per line
- Commands must be real, standard {os} commands that exist on this system
- Do NOT invent commands — only use well-known tools (chmod, chown, systemctl, ufw, sysctl, sed, etc.)
- Do NOT include ssh-agent, xauth, dbus, session management or unrelated daemon commands
- If the fix requires editing a config file, use sed or echo with a redirect
- If nothing can be fixed with a shell command, output exactly: NO_FIX_AVAILABLE
- Do NOT output anything else"""


class OllamaWorker(QThread):
    result_ready  = pyqtSignal(str)   # final full text (or error string)
    token_ready   = pyqtSignal(str)   # each streaming token
    status_update = pyqtSignal(str)

    def __init__(self, prompt: str, model: str, base_url: str):
        super().__init__()
        self.prompt   = prompt
        self.model    = model
        self.base_url = base_url

    def _model_exists(self) -> bool:
        try:
            url = self.base_url.rstrip("/") + "/api/tags"
            with urllib.request.urlopen(url, timeout=10) as resp:
                data = json.loads(resp.read())
                names = [m.get("name", "").split(":")[0] for m in data.get("models", [])]
                return self.model.split(":")[0] in names
        except Exception:
            return False

    def _pull_model(self) -> bool:
        try:
            self.status_update.emit(f"Pulling model '{self.model}'… (first run only)")
            url     = self.base_url.rstrip("/") + "/api/pull"
            payload = json.dumps({"name": self.model, "stream": False}).encode()
            req     = urllib.request.Request(
                url, data=payload, headers={"Content-Type": "application/json"}
            )
            with urllib.request.urlopen(req, timeout=300) as resp:
                data = json.loads(resp.read())
                if data.get("status") == "success":
                    return True
                self.result_ready.emit(f"[Pull returned unexpected status: {data.get('status')}]")
                return False
        except Exception as e:
            self.result_ready.emit(f"[Pull failed: {e}]")
            return False

    def run(self):
        if not self._model_exists():
            if not self._pull_model():
                return

        self.status_update.emit(f"Querying {self.model}…")
        url     = self.base_url.rstrip("/") + "/api/generate"
        payload = json.dumps({
            "model":  self.model,
            "prompt": self.prompt,
            "stream": True,
        }).encode()
        req = urllib.request.Request(
            url, data=payload, headers={"Content-Type": "application/json"}
        )
        try:
            full = []
            with urllib.request.urlopen(req, timeout=120) as resp:
                for raw_line in resp:
                    line = raw_line.strip()
                    if not line:
                        continue
                    try:
                        chunk = json.loads(line)
                    except Exception:
                        continue
                    token = chunk.get("response", "")
                    if token:
                        full.append(token)
                        self.token_ready.emit(token)
                    if chunk.get("done"):
                        break
            self.result_ready.emit("".join(full).strip())
        except urllib.error.URLError as e:
            self.result_ready.emit(f"[Ollama unreachable: {e.reason}]")
        except Exception as e:
            self.result_ready.emit(f"[Error: {e}]")


class ApplyWorker(QThread):
    progress = pyqtSignal(str)
    finished = pyqtSignal(str, str)  # summary, full output

    def __init__(self, cmds, blocked_paths, sudo_paths):
        super().__init__()
        self.cmds          = cmds
        self.blocked_paths = blocked_paths
        self.sudo_paths    = sudo_paths

    def run(self):
        results = []
        all_ok  = True
        for cmd in self.cmds:
            # Hard safety net — catches anything that slipped past the UI validator
            danger = RemediationDialog._check_danger(cmd)
            if danger or any(p in cmd for p in self.blocked_paths):
                all_ok = False
                reason = danger or "sensitive path"
                results.append(f"⛔  $ {cmd}\n[Blocked: {reason} — not executed]")
                continue

            run_cmd = cmd
            if not cmd.startswith("sudo ") and any(p in cmd for p in self.sudo_paths):
                run_cmd = "sudo -n " + cmd  # -n: fail immediately if password needed

            self.progress.emit(f"$ {cmd}")
            try:
                r = subprocess.run(
                    run_cmd, shell=True, capture_output=True, text=True, timeout=30
                )
                out = (r.stdout + r.stderr).strip() or "(no output)"
                ok  = r.returncode == 0
                if not ok:
                    all_ok = False
                    # sudo -n fails with "sudo: a password is required" — show manual hint
                    if "password is required" in out or "a password is required" in out:
                        results.append(
                            f"⚠  $ {cmd}\n"
                            f"[Needs sudo password — run manually:\n"
                            f"  sudo {cmd}]"
                        )
                        continue
                status  = "✓" if ok else f"✖ (exit {r.returncode})"
                display = f"sudo {cmd}" if run_cmd != cmd else cmd
                results.append(f"{status}  $ {display}\n{out}")
            except Exception as e:
                all_ok = False
                results.append(f"✖  $ {cmd}\nError: {e}")

        summary = "✓ All commands succeeded" if all_ok else "⚠ Some commands need manual review"
        self.finished.emit(summary, "\n\n".join(results))


class RemediationDialog(QDialog):
    def __init__(self, parent, section: str, finding: str,
                 ollama_url: str, ollama_model: str):
        super().__init__(parent)
        self.setWindowTitle(f"AI Fix — {section}")
        self.resize(700, 520)
        self.setStyleSheet(f"""
            QDialog   {{ background:{COLORS['bg2']}; color:{COLORS['text']}; }}
            QLabel    {{ color:{COLORS['text']}; font-size:12px; }}
            QTextEdit {{ background:{COLORS['bg3']}; color:{COLORS['text']};
                         border:1px solid {COLORS['border']}; border-radius:4px;
                         font-family:'JetBrains Mono','Fira Mono',monospace;
                         font-size:12px; padding:8px; }}
            QPushButton {{ background:{COLORS['bg3']}; color:{COLORS['cyan']};
                           border:1px solid {COLORS['border']}; border-radius:4px;
                           padding:7px 18px; font-size:12px; }}
            QPushButton#apply {{ background:{COLORS['cyan']}; color:{COLORS['bg']};
                                 font-weight:bold; }}
            QPushButton:hover  {{ border-color:{COLORS['cyan_dim']}; }}
            QPushButton:disabled {{ color:{COLORS['text3']}; border-color:{COLORS['bg3']}; }}
        """)

        self.applied_output = None
        layout = QVBoxLayout(self)
        layout.setSpacing(10)
        layout.setContentsMargins(16, 16, 16, 16)


        layout.addWidget(QLabel(f"<b style='color:{COLORS['cyan']}'>Section:</b> {section}"))

        lbl_f = QLabel("Finding:")
        lbl_f.setStyleSheet(f"color:{COLORS['text2']};")
        layout.addWidget(lbl_f)
        finding_view = QTextEdit()
        finding_view.setReadOnly(True)
        finding_view.setPlainText(finding[:900] + ("…" if len(finding) > 900 else ""))
        finding_view.setFixedHeight(120)
        layout.addWidget(finding_view)

        lbl_fix = QLabel("🤖  Ollama suggestion  (you can edit before applying):")
        lbl_fix.setStyleSheet(f"color:{COLORS['cyan']};font-weight:bold;")
        layout.addWidget(lbl_fix)

        self.lbl_ai_status = QLabel("⏳  Connecting to Ollama…")
        self.lbl_ai_status.setStyleSheet(f"color:{COLORS['text2']};font-size:11px;")
        layout.addWidget(self.lbl_ai_status)

        self.fix_view = QTextEdit()
        self.fix_view.setPlaceholderText("Response will appear here…")
        layout.addWidget(self.fix_view)

        lbl_warn = QLabel("⚠  Always review the command before applying.")
        lbl_warn.setStyleSheet(f"color:{COLORS['orange']};font-size:11px;")
        layout.addWidget(lbl_warn)

        btn_row = QHBoxLayout()
        self.btn_apply = QPushButton("▶  Apply Fix")
        self.btn_apply.setObjectName("apply")
        self.btn_apply.setEnabled(False)
        btn_skip = QPushButton("Close")
        btn_row.addWidget(self.btn_apply)
        btn_row.addStretch()
        btn_row.addWidget(btn_skip)
        layout.addLayout(btn_row)

        self.btn_apply.clicked.connect(self._apply)
        btn_skip.clicked.connect(self.reject)

        # Start Ollama query in background QThread
        prompt = REMEDIATION_PROMPT.format(
            os=_OS, section=section, finding=finding[:1200]
        )
        self._worker = OllamaWorker(prompt, ollama_model, ollama_url)
        self._worker.status_update.connect(self._on_status)
        self._worker.token_ready.connect(self._on_token)
        self._worker.result_ready.connect(self._on_result)
        self._worker.start()

    def _on_status(self, msg: str):
        self.lbl_ai_status.setText(f"⏳  {msg}")

    def _on_token(self, token: str):
        self.lbl_ai_status.setText(f"✍  Generating…")
        cursor = self.fix_view.textCursor()
        cursor.movePosition(cursor.MoveOperation.End)
        cursor.insertText(token)
        self.fix_view.setTextCursor(cursor)

    def _on_result(self, text: str):
        if text.startswith("["):
            self.lbl_ai_status.setText(f"✖  {text}")
            self.fix_view.setPlainText(text)
            return

        if not text or text == "NO_FIX_AVAILABLE":
            self.lbl_ai_status.setText("ℹ  No automated fix available for this finding.")
            self.fix_view.setPlainText(text or "NO_FIX_AVAILABLE")
            return

        # Validate every command and annotate dangerous ones in-place
        lines     = text.splitlines()
        annotated = []
        has_danger = False
        for line in lines:
            danger = self._check_danger(line.strip())
            if danger:
                has_danger = True
                annotated.append(f"# ⛔ BLOCKED — {danger}\n# {line}")
            else:
                annotated.append(line)

        self.fix_view.setPlainText("\n".join(annotated))

        if has_danger:
            self.lbl_ai_status.setText(
                "⚠  Dangerous commands detected (blocked with # ⛔) — review before applying"
            )
            self.lbl_ai_status.setStyleSheet(f"color:{COLORS['orange']};font-size:11px;font-weight:bold;")
        else:
            self.lbl_ai_status.setText("✓  Done — review and edit before applying")
        self.btn_apply.setEnabled(True)

    # Patterns that indicate a command is too dangerous to auto-run.
    # Each entry is (regex_pattern, human_reason).
    _DANGER_PATTERNS = [
        (r"sudoers",                  "modifies sudoers — use visudo"),
        (r"/etc/shadow",              "modifies shadow password file"),
        (r"/etc/passwd",              "modifies passwd file"),
        (r"rm\s+-[a-z]*r[a-z]*f?\s+/(?!\S)",  "rm -rf on root"),
        (r"rm\s+-[a-z]*f?[a-z]*r\s+/(?!\S)",  "rm -rf on root"),
        (r">\s*/dev/sd[a-z]",         "overwrites block device"),
        (r"dd\s+.*of=/dev/",          "dd to block device"),
        (r"mkfs",                     "formats a filesystem"),
        (r":()\s*\{",                 "fork bomb"),
        (r"chmod\s+[0-9]*[0-7][0-7][0-7]\s+/etc/(?:passwd|shadow|sudoers|ssh)", "unsafe chmod on critical file"),
        (r">\s*/etc/(?:passwd|shadow|sudoers|crontab|hosts)(?:\s|$)", "overwrites critical config"),
        (r"curl\s+.*\|\s*(?:ba)?sh",  "remote code execution via pipe"),
        (r"wget\s+.*-O\s*-\s*\|",     "remote code execution via pipe"),
        (r"base64\s+.*\|\s*(?:ba)?sh","obfuscated remote execution"),
        (r"!!!", "invalid sudoers syntax"),
    ]

    @classmethod
    def _check_danger(cls, cmd: str) -> str:
        """Return a human-readable reason if cmd is dangerous, else empty string."""
        if not cmd or cmd.startswith("#"):
            return ""
        for pattern, reason in cls._DANGER_PATTERNS:
            if re.search(pattern, cmd, re.IGNORECASE):
                return reason
        return ""

    # These paths are too dangerous to auto-execute even with sudo — always show manually
    _BLOCKED_PATHS = (
        "/etc/sudoers",
        "/etc/sudoers.d/",
        "/etc/shadow",
        "/etc/passwd",
        "/etc/ssh/sshd_config",
        "/etc/crontab",
        "/etc/cron.d/",
        "/etc/hosts",
    )

    # Commands targeting these path prefixes need root but are safe to auto-sudo
    _SUDO_PATHS = (
        "/etc/",
        "/usr/",
        "/var/",
        "/sys/",
        "/boot/",
        "/lib/",
        "/lib64/",
        "/sbin/",
        "/bin/",
    )

    @staticmethod
    def _clean_commands(raw: str) -> list[str]:
        """Strip LLM formatting noise and return executable command lines."""
        import re
        cmds = []
        for line in raw.splitlines():
            line = line.strip()
            if not line:
                continue
            # skip parenthetical notes and explanations
            if line.startswith("(") or line.startswith("#"):
                continue
            # strip leading "1." "2." "- " bullet formatting
            line = re.sub(r"^\d+\.\s*", "", line)
            line = re.sub(r"^[-*]\s*", "", line)
            # strip surrounding backticks
            line = line.strip("`").strip()
            if not line or line == "NO_FIX_AVAILABLE":
                continue

            # Fix unquoted echo content that contains shell metacharacters.
            # Example: echo neo ALL=(ALL) NOPASSWD: ... >> /etc/sudoers
            #   → echo 'neo ALL=(ALL) NOPASSWD: ...' >> /etc/sudoers
            # /bin/sh (dash) treats bare (...) in argument position as a
            # compound command — wrapping in single quotes prevents this.
            echo_m = re.match(r'^(echo\s+)(.*?)(\s*>>?\s*\S+.*)$', line, re.DOTALL)
            if echo_m:
                prefix, content, redirect = echo_m.groups()
                already_quoted = (
                    (content.startswith("'") and content.endswith("'")) or
                    (content.startswith('"') and content.endswith('"'))
                )
                if not already_quoted and re.search(r"[()!$`\\]", content):
                    # Escape any single quotes inside content, then wrap
                    content = "'" + content.replace("'", "'\\''") + "'"
                    line = prefix + content + redirect

            cmds.append(line)
        return cmds

    def _apply(self):
        raw = self.fix_view.toPlainText().strip()
        if not raw:
            return
        cmds = self._clean_commands(raw)
        if not cmds:
            self.applied_output = "No executable commands found in suggestion."
            self.accept()
            return

        self.btn_apply.setEnabled(False)
        self.btn_apply.setText("⏳  Running…")
        self.lbl_ai_status.setText("⏳  Applying fix…")

        self._apply_worker = ApplyWorker(cmds, self._BLOCKED_PATHS, self._SUDO_PATHS)
        self._apply_worker.progress.connect(self._on_apply_progress)
        self._apply_worker.finished.connect(self._on_apply_done)
        self._apply_worker.start()

    def _on_apply_progress(self, line: str):
        self.lbl_ai_status.setText(f"⏳  {line}")

    def _on_apply_done(self, summary: str, output: str):
        self.applied_output = f"{summary}\n\n{output}"
        self.accept()


# ============================================================
# HUVUD FÖNSTER
# ============================================================
class SecurityAuditWindow(QMainWindow):
    def __init__(self):
        super().__init__()
        self.setWindowTitle(f"{APP_NAME} v{VERSION}")
        self.resize(1200, 800)
        self.results  = {}
        self.worker   = None
        self._apply_theme()
        self._build_ui()

    def _apply_theme(self):
        self.setStyleSheet(f"""
            QMainWindow, QWidget {{
                background-color: {COLORS['bg']};
                color: {COLORS['text']};
                font-family: 'JetBrains Mono', 'Fira Mono', 'Courier New', monospace;
                font-size: 12px;
            }}
            QScrollBar:vertical {{
                background: {COLORS['bg2']};
                width: 6px;
                border: none;
            }}
            QScrollBar::handle:vertical {{
                background: {COLORS['border']};
                min-height: 20px;
                border-radius: 3px;
            }}
            QScrollBar::add-line:vertical, QScrollBar::sub-line:vertical {{ height: 0; }}
            QListWidget {{
                background: {COLORS['bg2']};
                border: 1px solid {COLORS['border']};
                border-radius: 4px;
                outline: none;
            }}
            QListWidget::item {{
                padding: 6px 10px;
                border-bottom: 1px solid {COLORS['bg3']};
            }}
            QListWidget::item:selected {{
                background: #1a1a2e;
            }}
            QListWidget::item:hover {{
                background: {COLORS['bg3']};
            }}
            QPushButton {{
                background: {COLORS['bg3']};
                color: {COLORS['cyan']};
                border: 1px solid {COLORS['border']};
                border-radius: 4px;
                padding: 6px 14px;
                font-size: 11px;
            }}
            QPushButton:hover {{
                background: {COLORS['border']};
                border-color: {COLORS['cyan_dim']};
            }}
            QPushButton:disabled {{
                color: {COLORS['text3']};
                border-color: {COLORS['bg3']};
            }}
            QPushButton#btn_run {{
                background: {COLORS['cyan']};
                color: {COLORS['bg']};
                font-weight: bold;
            }}
            QPushButton#btn_run:hover {{
                background: {COLORS['cyan_dim']};
            }}
            QTextEdit {{
                background: {COLORS['bg2']};
                color: {COLORS['text']};
                border: 1px solid {COLORS['border']};
                border-radius: 4px;
                padding: 10px;
                font-family: 'JetBrains Mono', 'Fira Mono', 'Courier New', monospace;
                font-size: 13px;
                line-height: 1.5;
            }}
            QProgressBar {{
                background: {COLORS['bg3']};
                border: 1px solid {COLORS['border']};
                border-radius: 3px;
                height: 6px;
                text-align: center;
            }}
            QProgressBar::chunk {{
                background: {COLORS['cyan']};
                border-radius: 3px;
            }}
            QLabel#title {{
                color: {COLORS['cyan']};
                font-size: 16px;
                font-weight: bold;
                letter-spacing: 2px;
            }}
            QLabel#subtitle {{
                color: {COLORS['text3']};
                font-size: 10px;
            }}
            QFrame#sidebar {{
                background: {COLORS['bg2']};
                border-right: 1px solid {COLORS['border']};
            }}
        """)

    def _build_ui(self):
        central = LatticeWidget()
        central.setAutoFillBackground(True)
        pal = central.palette()
        pal.setColor(QPalette.ColorRole.Window, QColor(COLORS["bg"]))
        central.setPalette(pal)
        self.setCentralWidget(central)

        root = QHBoxLayout(central)
        root.setContentsMargins(0, 0, 0, 0)
        root.setSpacing(0)

        # ── SIDEBAR ──────────────────────────────────────────
        sidebar = QFrame()
        sidebar.setObjectName("sidebar")
        sidebar.setFixedWidth(220)
        sb = QVBoxLayout(sidebar)
        sb.setContentsMargins(12, 16, 12, 12)
        sb.setSpacing(8)

        lbl_title = QLabel("ÆGIS")
        lbl_title.setObjectName("title")
        sb.addWidget(lbl_title)

        lbl_sub = QLabel(f"Security Audit  v{VERSION}  [{_OS}]")
        lbl_sub.setObjectName("subtitle")
        sb.addWidget(lbl_sub)

        sb.addSpacing(12)

        self.section_list = QListWidget()
        for s in SECTIONS:
            item = QListWidgetItem(f"  {s}")
            item.setForeground(QColor(COLORS["text2"]))
            self.section_list.addItem(item)
        self.section_list.currentRowChanged.connect(self._on_section_select)
        sb.addWidget(self.section_list)

        sb.addSpacing(8)

        self.progress_bar = QProgressBar()
        self.progress_bar.setRange(0, len(AUDIT_SECTIONS))
        self.progress_bar.setValue(0)
        self.progress_bar.setTextVisible(False)
        sb.addWidget(self.progress_bar)

        self.lbl_status = QLabel("Ready")
        self.lbl_status.setStyleSheet(f"color: {COLORS['text3']}; font-size: 10px;")
        sb.addWidget(self.lbl_status)

        sb.addSpacing(8)

        btn_run = QPushButton("▶  Run Audit")
        btn_run.setObjectName("btn_run")
        btn_run.clicked.connect(self._run_audit)
        sb.addWidget(btn_run)
        self.btn_run = btn_run

        btn_export = QPushButton("↓  Export JSON")
        btn_export.clicked.connect(self._export)
        btn_export.setEnabled(False)
        sb.addWidget(btn_export)
        self.btn_export = btn_export

        btn_stop = QPushButton("■  Stop")
        btn_stop.clicked.connect(self._stop_audit)
        btn_stop.setEnabled(False)
        sb.addWidget(btn_stop)
        self.btn_stop = btn_stop

        sb.addSpacing(8)

        # ── Ollama settings ───────────────────────────────────

        lbl_ollama = QLabel("Ollama")
        lbl_ollama.setStyleSheet(f"color:{COLORS['text3']};font-size:10px;letter-spacing:1px;")
        sb.addWidget(lbl_ollama)

        self.ollama_url = QLineEdit("http://localhost:11434")
        self.ollama_url.setPlaceholderText("Ollama URL")
        self.ollama_url.setStyleSheet(
            f"background:{COLORS['bg3']};color:{COLORS['text2']};border:1px solid {COLORS['border']};"
            f"border-radius:4px;padding:3px 6px;font-size:10px;"
        )
        sb.addWidget(self.ollama_url)

        self.ollama_model = QLineEdit("llama3.2")
        self.ollama_model.setPlaceholderText("model name")
        self.ollama_model.setStyleSheet(
            f"background:{COLORS['bg3']};color:{COLORS['text2']};border:1px solid {COLORS['border']};"
            f"border-radius:4px;padding:3px 6px;font-size:10px;"
        )
        sb.addWidget(self.ollama_model)

        btn_ai_fix = QPushButton("🤖  AI Fix (Ollama)")
        btn_ai_fix.clicked.connect(self._ai_fix_current)
        btn_ai_fix.setEnabled(False)
        btn_ai_fix.setToolTip("Ask Ollama to suggest a fix for the selected section")
        sb.addWidget(btn_ai_fix)
        self.btn_ai_fix = btn_ai_fix

        sb.addStretch()
        root.addWidget(sidebar)

        # ── MAIN AREA ─────────────────────────────────────────
        main_area = QWidget()
        main_layout = QVBoxLayout(main_area)
        main_layout.setContentsMargins(16, 16, 16, 16)
        main_layout.setSpacing(8)

        self.lbl_section = QLabel("Select a section →")
        self.lbl_section.setStyleSheet(
            f"color: {COLORS['cyan']}; font-size: 14px; font-weight: bold;"
        )
        main_layout.addWidget(self.lbl_section)

        self.lbl_section_status = QLabel("")
        self.lbl_section_status.setStyleSheet(f"color: {COLORS['text3']}; font-size: 10px;")
        main_layout.addWidget(self.lbl_section_status)

        # ── Virus scan toolbar (only visible for Virus Scan) ──

        self.scan_toolbar = QWidget()
        scan_tb_layout = QHBoxLayout(self.scan_toolbar)
        scan_tb_layout.setContentsMargins(0, 0, 0, 4)
        scan_tb_layout.setSpacing(6)

        lbl_path = QLabel("Path:")
        lbl_path.setStyleSheet(f"color:{COLORS['text2']};font-size:12px;")
        scan_tb_layout.addWidget(lbl_path)

        self.scan_path_input = QLineEdit(os.path.expanduser("~"))
        self.scan_path_input.setStyleSheet(
            f"background:{COLORS['bg3']};color:{COLORS['text']};border:1px solid {COLORS['border']};"
            f"border-radius:4px;padding:5px 8px;font-size:12px;"
        )
        scan_tb_layout.addWidget(self.scan_path_input, stretch=1)

        btn_browse = QPushButton("Browse…")
        btn_browse.setFixedWidth(80)
        btn_browse.clicked.connect(self._browse_scan_path)
        scan_tb_layout.addWidget(btn_browse)

        self.btn_run_scan = QPushButton("▶  Run Virus Scan")
        self.btn_run_scan.setObjectName("btn_run")
        self.btn_run_scan.setFixedWidth(150)
        self.btn_run_scan.clicked.connect(self._run_virus_scan)
        scan_tb_layout.addWidget(self.btn_run_scan)

        self.btn_stop_scan = QPushButton("■  Stop")
        self.btn_stop_scan.setFixedWidth(70)
        self.btn_stop_scan.setEnabled(False)
        self.btn_stop_scan.clicked.connect(self._stop_virus_scan)
        scan_tb_layout.addWidget(self.btn_stop_scan)

        self.scan_toolbar.setVisible(False)
        main_layout.addWidget(self.scan_toolbar)

        self.output_view = QTextEdit()
        self.output_view.setReadOnly(True)
        self.output_view.setPlaceholderText("Run audit to populate results...")
        main_layout.addWidget(self.output_view)

        root.addWidget(main_area)

        self.section_list.setCurrentRow(0)

    def _browse_scan_path(self):
        path = QFileDialog.getExistingDirectory(self, "Select scan directory",
                                                self.scan_path_input.text())
        if path:
            self.scan_path_input.setText(path)

    def _on_section_select(self, row):
        if row < 0:
            return
        section = SECTIONS[row]
        self.lbl_section.setText(section)
        is_virus = section == VIRUS_SECTION
        self.scan_toolbar.setVisible(is_virus)
        if section in self.results:
            status, output = self.results[section]
            self._show_output(status, output)
            self.btn_ai_fix.setEnabled(status in ("warn", "critical", "error"))
        else:
            self.output_view.clear()
            if is_virus:
                self.lbl_section_status.setText("Choose a path and click Run Virus Scan")
            else:
                self.lbl_section_status.setText("Not yet scanned")
            self.btn_ai_fix.setEnabled(False)

    def _show_output(self, status, output):
        colors = {
            "ok":       COLORS["green"],
            "warn":     COLORS["orange"],
            "critical": COLORS["red"],
            "error":    COLORS["red"],
        }
        labels = {
            "ok":       "✓ OK",
            "warn":     "⚠  WARNING",
            "critical": "✖ CRITICAL",
            "error":    "✖ ERROR",
        }
        c = colors.get(status, COLORS["text2"])
        l = labels.get(status, status.upper())
        self.lbl_section_status.setText(l)
        self.lbl_section_status.setStyleSheet(f"color:{c};font-size:11px;font-weight:bold;")
        escaped = output.replace("&", "&amp;").replace("<", "&lt;").replace(">", "&gt;")
        html_lines = []
        for line in escaped.splitlines():
            if line.startswith("⚠") or "WARNING" in line or "FOUND" in line:
                html_lines.append(f'<span style="color:{COLORS["orange"]}">{line}</span>')
            elif line.startswith("✖") or "ERROR" in line or "CRITICAL" in line:
                html_lines.append(f'<span style="color:{COLORS["red"]}">{line}</span>')
            elif line.startswith("✓") or "OK" in line or "Clean" in line:
                html_lines.append(f'<span style="color:{COLORS["green"]}">{line}</span>')
            else:
                html_lines.append(f'<span style="color:{COLORS["text"]}">{line}</span>')
        html = (
            f'<div style="font-family:\'JetBrains Mono\',\'Fira Mono\',monospace;'
            f'font-size:13px;line-height:1.7;background:{COLORS["bg2"]};'
            f'color:{COLORS["text"]};padding:4px">'
            + "<br>".join(html_lines)
            + "</div>"
        )
        self.output_view.setHtml(html)

    def _run_audit(self):
        self.results = {}
        self._scan_log = []
        self.progress_bar.setRange(0, len(AUDIT_SECTIONS))
        self.progress_bar.setValue(0)
        self._sections_done = 0
        for i, s in enumerate(SECTIONS):
            item = self.section_list.item(i)
            item.setText(f"  {s}")
            item.setForeground(QColor(COLORS["text3"]))
            item.setBackground(QColor(COLORS["bg2"]))
        self.btn_run.setEnabled(False)
        self.btn_stop.setEnabled(True)
        self.btn_export.setEnabled(False)
        self.btn_ai_fix.setEnabled(False)
        self.lbl_status.setText("Running...")
        self.worker = AuditWorker(AUDIT_SECTIONS)
        self.worker.section_done.connect(self._on_section_done)
        self.worker.all_done.connect(self._on_all_done)
        self.worker.start()

    def _run_virus_scan(self):
        scan_path = self.scan_path_input.text().strip() or os.path.expanduser("~")
        self._scan_log = []
        self.output_view.clear()
        self.lbl_section_status.setText("Scanning…")
        self.lbl_section_status.setStyleSheet(f"color:{COLORS['cyan']};font-size:10px;")
        self.btn_run_scan.setEnabled(False)
        self.btn_stop_scan.setEnabled(True)
        self.scan_worker = AuditWorker([VIRUS_SECTION], scan_path=scan_path)
        self.scan_worker.section_done.connect(self._on_virus_scan_done)
        self.scan_worker.scan_progress.connect(self._on_scan_progress)
        self.scan_worker.start()

    def _stop_virus_scan(self):
        if hasattr(self, "scan_worker"):
            self.scan_worker.stop()
        self.btn_run_scan.setEnabled(True)
        self.btn_stop_scan.setEnabled(False)
        self.lbl_section_status.setText("Stopped")

    def _on_virus_scan_done(self, section, status, output):
        self.results[section] = (status, output)
        self.btn_run_scan.setEnabled(True)
        self.btn_stop_scan.setEnabled(False)
        self._show_output(status, output)
        self.btn_ai_fix.setEnabled(status in ("warn", "critical", "error"))

    def _stop_audit(self):
        if self.worker:
            self.worker.stop()
        self.btn_stop.setEnabled(False)
        self.lbl_status.setText("Stopped")

    def _on_section_done(self, section, status, output):
        self.results[section] = (status, output)
        self._sections_done += 1
        self.progress_bar.setValue(self._sections_done)
        idx = SECTIONS.index(section)
        item = self.section_list.item(idx)

        fg_map = {
            "ok":       COLORS["green"],
            "warn":     COLORS["orange"],
            "critical": COLORS["red"],
            "error":    COLORS["red"],
        }
        bg_map = {
            "ok":       "#0a1a0a",
            "warn":     "#1f1200",
            "critical": "#1f0000",
            "error":    "#1f0000",
        }
        prefix_map = {
            "ok":       "✓ ",
            "warn":     "⚠ ",
            "critical": "✖ ",
            "error":    "✖ ",
        }
        prefix = prefix_map.get(status, "  ")
        item.setText(f"{prefix}{section}")
        item.setForeground(QColor(fg_map.get(status, COLORS["text"])))
        item.setBackground(QColor(bg_map.get(status, COLORS["bg2"])))

        if self.section_list.currentRow() == idx:
            self.lbl_section.setText(section)
            self._show_output(status, output)
        self.lbl_status.setText(f"{self._sections_done}/{len(AUDIT_SECTIONS)} done")

    def _on_scan_progress(self, label, count):
        self.lbl_status.setText(label)
        self._scan_log.append(label)
        idx = SECTIONS.index(VIRUS_SECTION)
        if self.section_list.currentRow() == idx:
            # Trim to last 300 lines smoothly
            if len(self._scan_log) > 300:
                self._scan_log = self._scan_log[-300:]
                self.output_view.setPlainText("\n".join(self._scan_log))
            else:
                self.output_view.append(label)
            sb = self.output_view.verticalScrollBar()
            sb.setValue(sb.maximum())

    def _on_all_done(self):
        self.btn_run.setEnabled(True)
        self.btn_stop.setEnabled(False)
        self.btn_export.setEnabled(True)
        warnings = [(s, st, out) for s, (st, out) in self.results.items()
                    if st in ("warn", "critical", "error")]
        if warnings:
            self.lbl_status.setText(f"Done — {len(warnings)} warning(s)")
            self.lbl_status.setStyleSheet(f"color:{COLORS['orange']};font-size:10px;")
            self.btn_ai_fix.setEnabled(True)
            self._show_summary(warnings)
        else:
            self.lbl_status.setText("Audit complete — no issues found")
            self.lbl_status.setStyleSheet(f"color:{COLORS['green']};font-size:10px;")
            self._show_summary([])

    def _show_summary(self, warnings):
        self.lbl_section.setText("Audit Summary")
        self.lbl_section_status.setText("")
        self.scan_toolbar.setVisible(False)

        # ── Audit score ──────────────────────────────────────────────
        total = len(AUDIT_SECTIONS)
        warn_count     = sum(1 for _, st, _ in warnings if st == "warn")
        critical_count = sum(1 for _, st, _ in warnings if st in ("critical", "error"))
        score = max(0, 100 - warn_count * 5 - critical_count * 15)
        bar_filled = round(score / 5)   # 20-block bar, each block = 5 pts
        bar = "█" * bar_filled + "░" * (20 - bar_filled)
        if score >= 80:
            score_color = COLORS["green"]
            grade = "GOOD"
        elif score >= 50:
            score_color = COLORS["orange"]
            grade = "FAIR"
        else:
            score_color = COLORS["red"]
            grade = "POOR"

        score_html = (
            f'<div style="margin-bottom:16px;padding:12px 14px;'
            f'background:{COLORS["bg3"]};border-radius:6px;'
            f'border:1px solid {score_color}33">'
            f'<div style="color:{COLORS["text2"]};font-size:11px;margin-bottom:6px">'
            f'AUDIT SCORE</div>'
            f'<div style="display:flex;align-items:baseline;gap:12px">'
            f'<span style="color:{score_color};font-size:28px;font-weight:bold">{score}</span>'
            f'<span style="color:{score_color};font-size:12px;font-weight:bold">{grade}</span>'
            f'<span style="color:{COLORS["text2"]};font-size:11px">'
            f'/ 100 &nbsp;·&nbsp; {total - len(warnings)}/{total} sections clean</span>'
            f'</div>'
            f'<div style="color:{score_color};font-size:13px;letter-spacing:1px;margin-top:6px">'
            f'{bar}</div>'
            f'</div>'
        )

        if not warnings:
            self.output_view.setHtml(
                f'<div style="font-family:\'JetBrains Mono\',\'Fira Mono\',monospace;'
                f'background:{COLORS["bg2"]};color:{COLORS["text"]};padding:4px">'
                + score_html
                + f'<div style="color:{COLORS["green"]};font-size:13px;font-weight:bold">'
                  f'✓ All sections clean</div></div>'
            )
            return

        icon = {"warn": "⚠", "critical": "✖", "error": "✖"}
        color = {"warn": COLORS["orange"], "critical": COLORS["red"], "error": COLORS["red"]}

        lines = [
            score_html,
            f'<div style="color:{COLORS["orange"]};font-size:12px;font-weight:bold;'
            f'margin-bottom:12px">{len(warnings)} issue(s) found — click a section for details</div>',
        ]

        for section, status, output in warnings:
            c = color.get(status, COLORS["orange"])
            ic = icon.get(status, "⚠")
            preview_lines = [l for l in output.splitlines() if l.strip()][:6]
            preview = "<br>".join(
                f'<span style="color:{COLORS["text"]}">{l}</span>'
                for l in preview_lines
            )
            lines.append(
                f'<div style="margin-bottom:14px;padding:10px 12px;'
                f'background:{COLORS["bg3"]};border-left:3px solid {c};border-radius:4px">'
                f'<div style="color:{c};font-weight:bold;font-size:13px;margin-bottom:6px">'
                f'{ic} {section}</div>'
                f'<div style="font-size:12px;line-height:1.6">{preview}</div>'
                f'</div>'
            )

        self.output_view.setHtml(
            f'<div style="font-family:\'JetBrains Mono\',\'Fira Mono\',monospace;'
            f'background:{COLORS["bg2"]};color:{COLORS["text"]};padding:4px">'
            + "".join(lines) + "</div>"
        )

    def _ai_fix_current(self):
        from PyQt6.QtWidgets import QMessageBox
        row = self.section_list.currentRow()
        if row < 0:
            QMessageBox.information(self, "AI Fix", "Select a warning section first.")
            return
        section = SECTIONS[row]
        if section not in self.results:
            QMessageBox.information(self, "AI Fix", f"No results yet for: {section}")
            return
        status, output = self.results[section]
        if status not in ("warn", "critical", "error"):
            QMessageBox.information(self, "AI Fix",
                f"'{section}' has no issues to fix (status: {status}).\n"
                "Click on a ⚠ or ✖ section in the list first.")
            return
        try:
            dlg = RemediationDialog(
                self, section, output,
                ollama_url=self.ollama_url.text().strip(),
                ollama_model=self.ollama_model.text().strip(),
            )
            dlg.exec()
            if dlg.applied_output:
                self.results[section] = (status, output + "\n\n── Applied fix ──\n" + dlg.applied_output)
                self._show_output(status, self.results[section][1])
        except Exception as e:
            QMessageBox.critical(self, "AI Fix Error", str(e))

    def _export(self):
        path, _ = QFileDialog.getSaveFileName(
            self,
            "Export Audit Report",
            f"aegis_audit_{datetime.date.today()}.json",
            "JSON Files (*.json)",
        )
        if not path:
            return

        SENSITIVE = {"Sudo / Privileges", "SSH Config", "Users & Groups"}
        results_export = {}
        for s, (st, out) in self.results.items():
            if s in SENSITIVE:
                results_export[s] = {
                    "status": st,
                    "output": "[REDACTED — sensitive data omitted from export]",
                }
            else:
                results_export[s] = {"status": st, "output": out}

        export_data = {
            "tool":      APP_NAME,
            "version":   VERSION,
            "platform":  _OS,
            "timestamp": datetime.datetime.now().isoformat(),
            "hostname":  socket.gethostname(),
            "note":      "Sensitive sections (Sudo/Privileges, SSH Config, Users & Groups) are redacted.",
            "results":   results_export,
        }
        try:
            with open(path, "w") as f:
                json.dump(export_data, f, indent=2)
            # Restrict file permissions (Unix only — no-op on Windows)
            if not IS_WIN:
                os.chmod(path, 0o600)
                self.lbl_status.setText(f"Exported → {os.path.basename(path)}  (chmod 600)")
            else:
                self.lbl_status.setText(f"Exported → {os.path.basename(path)}")
        except Exception as e:
            self.lbl_status.setText(f"Export failed: {e}")


# ============================================================
# ENTRY POINT
# ============================================================
def main():
    try:
        import psutil  # noqa
    except ImportError:
        print("psutil not installed. Run: pip install psutil")
        sys.exit(1)

    app = QApplication(sys.argv)
    app.setApplicationName(APP_NAME)
    app.setApplicationVersion(VERSION)
    win = SecurityAuditWindow()
    win.show()
    sys.exit(app.exec())


if __name__ == "__main__":
    main()
