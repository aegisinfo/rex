# rex

**ÆGIS Security Audit** — a local, offline security auditing tool with an AI-powered fix assistant.

Single Python file. No server. No telemetry. Runs entirely on your machine.

---

## Features

- **14 audit sections** — system info, open ports, firewall, SSH config, SUID/SGID files, world-writable files, sudo privileges, startup services, scheduled tasks, and more
- **Virus scan** — ClamAV integration (optional)
- **AI Fix (Ollama)** — select any finding, ask the local LLM for a remediation, review the suggested commands, and apply them with one click
- **Export** — save the full audit report as a `.txt` file
- Cross-platform: Linux · macOS · Windows

---

## Requirements

- Python 3.10+
- [Ollama](https://ollama.com) (optional — only needed for AI Fix)

---

## Install

```bash
git clone https://github.com/aegisinfo/rex
cd rex
pip install -r requirements.txt
python rex.py
```

Or without cloning:

```bash
pip install PyQt6 psutil
curl -O https://raw.githubusercontent.com/aegisinfo/rex/main/rex.py
python rex.py
```

---

## AI Fix (Ollama)

rex uses [Ollama](https://ollama.com) for local, private AI-assisted remediation. No API key needed.

1. Install Ollama: https://ollama.com/download
2. Pull a model: `ollama pull llama3.2`
3. Start the server: `ollama serve`
4. In rex: select a finding → click **AI Fix** → review commands → **Apply Fix**

> **Security note:** rex previews all suggested commands before running them. Commands targeting sensitive system paths (`/etc/sudoers`, `/etc/shadow`, `/etc/passwd`, `/etc/ssh/sshd_config`) are never auto-executed — they are shown for manual review only. All other system-path commands are run with `sudo`.

---

## Audit sections

| Section | What it checks |
|---|---|
| System Info | OS, kernel, hostname, uptime |
| CPU & Memory | load average, RAM/swap usage |
| Disk | partition usage, mount flags |
| Network | interfaces, IPs, MAC addresses |
| Open Ports | listening TCP/UDP ports and owning processes |
| Running Processes | top processes by CPU/memory |
| Startup Services | enabled systemd / launchd / startup items |
| Firewall | ufw / iptables / pf / Windows Firewall status |
| Users & Groups | local accounts, sudoers membership |
| Sudo / Privileges | sudoers file analysis, NOPASSWD entries |
| SSH Config | PermitRootLogin, PasswordAuthentication, key settings |
| Scheduled Tasks | crontab entries, systemd timers, Task Scheduler |
| SUID/SGID Files | setuid/setgid binaries outside standard paths |
| World-Writable Files | files/dirs writable by any user |
| Virus Scan | ClamAV scan of home directory (if installed) |

---

## Screenshot

_Coming soon_

---

## License

MIT — see [LICENSE](LICENSE)

---

Built by [Niklas Borneklint](https://aegiscloud.org) · part of the [AEGIS](https://github.com/aegisinfo) ecosystem
