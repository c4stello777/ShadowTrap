# ShadowTrap 🪤

Interactive SSH honeypot + multi-port decoy. Simulates a fake Linux shell to capture brute-force logins, attacker commands, and intrusion probes with GeoIP profiling, file logging, and Discord alerts.

![Python](https://img.shields.io/badge/Python-3.10%2B-blue) ![Paramiko](https://img.shields.io/badge/SSH-Paramiko-green) ![Docker](https://img.shields.io/badge/Docker-ready-blue) ![License](https://img.shields.io/badge/License-MIT-green)

## Features

| Capability | Details |
|---|---|
| Fake SSH shell | `ls`, `whoami`, `uname -a`, `cat` (denied), unknown-command handling, `exit` |
| Credential capture | Logs every `user/pass` combo, grants shell only for configured pair |
| Multi-port decoys | `21 FTP, 23 Telnet, 25 SMTP, 53 DNS, 80 HTTP, 110 POP3, 143 IMAP, 3306 MySQL, 445 SMB, 3389 RDP` |
| GeoIP + Discord | `ipapi.co` country/city/org/ASN on first sight per IP + webhook alerts |
| Logging | `ssh_honeypot.log` with timestamps, console + file |
| Config via env | No hardcoded secrets - all in `.env` |

## How it works

```
attacker -> :2222 (SSH) -> Paramiko Transport -> SSHHandler.check_auth_password -> log + Discord
        -> shell? -> fake Ubuntu prompt -> command logged -> canned response
attacker -> :21/:23/:80... -> fake_service banner -> log + GeoIP -> close
```

## Requirements

- Linux (Ubuntu / Kali / Debian), `python3.10+`, `git`
- `ssh-keygen` (openssh-client)
- Docker optional but recommended
- Discord webhook URL (optional)

## Installation - Linux bare-metal

```bash
sudo apt update && sudo apt install -y python3 python3-venv git openssh-client

git clone https://github.com/c4stello777/ShadowTrap.git
cd ShadowTrap

python3 -m venv venv
source venv/bin/activate
pip install -r requirements.txt

# 1. host key (required - Paramiko needs this file)
ssh-keygen -t rsa -b 2048 -m PEM -f server_rsa.key -N ""
chmod 600 server_rsa.key

# 2. config
cp .env.example .env
nano .env
# DISCORD_WEBHOOK_URL=https://discord.com/api/webhooks/.../...
# SSH_PORT=2222
# HONEYPOT_USER=admin
# HONEYPOT_PASS=admin

# 3. run (2222 avoids root + sshd conflict)
python pot.py
```

Expose on real SSH port 22 (optional):

```bash
# option A: run as root on 22
sudo SSH_PORT=22 venv/bin/python pot.py

# option B: redirect 22 -> 2222 (keeps honeypot unprivileged)
sudo iptables -t nat -A PREROUTING -p tcp --dport 22 -j REDIRECT --to-port 2222
# persist with iptables-persistent or ufw route
```

Run in background with systemd:

```ini
# /etc/systemd/system/shadowtrap.service
[Unit]
Description=ShadowTrap SSH Honeypot
After=network.target
[Service]
WorkingDirectory=/opt/ShadowTrap
EnvironmentFile=/opt/ShadowTrap/.env
ExecStart=/opt/ShadowTrap/venv/bin/python /opt/ShadowTrap/pot.py
Restart=always
[Install]
WantedBy=multi-user.target
```
```bash
sudo systemctl daemon-reload && sudo systemctl enable --now shadowtrap
journalctl -u shadowtrap -f
```

## Installation - Docker (recommended for isolation)

```bash
git clone https://github.com/c4stello777/ShadowTrap.git
cd ShadowTrap
cp .env.example .env
nano .env  # set DISCORD_WEBHOOK_URL

ssh-keygen -t rsa -b 2048 -m PEM -f server_rsa.key -N ""

docker compose up -d --build
docker logs -f shadowtrap
cat ssh_honeypot.log
```

Ports: host `2222->2222 (SSH)`, `2121->21`, `2323->23`, `2525->25`, `8080->80`, etc. Change in `docker-compose.yml` as needed. Logs and key are mounted volumes.

## Configuration (.env)

| Var | Default | Purpose |
|---|---|---|
| `DISCORD_WEBHOOK_URL` | empty (disabled) | Discord channel webhook for alerts |
| `SSH_PORT` | `2222` | SSH listen port |
| `HONEYPOT_USER` / `HONEYPOT_PASS` | `admin` / `admin` | Only pair that gets fake shell (all attempts logged) |
| `HOST_KEY_FILE` | `server_rsa.key` | Paramiko RSA host key path |
| `LOGFILE` | `ssh_honeypot.log` | Log file |

## Test it

```bash
# successful login (gets fake shell)
ssh -p 2222 admin@127.0.0.1
# password: admin
# try: whoami, ls, uname -a, cat /etc/passwd, badcmd, exit

# failed login (still logged)
ssh -p 2222 root@127.0.0.1

# decoy banner
nc -v 127.0.0.1 21
curl -i http://127.0.0.1:8080/

# check intel
cat ssh_honeypot.log
```

Expected log:

```
[2025-08-12 18:40:01] SSH Honeypot started on port 2222
[2025-08-12 18:40:10] Incoming SSH connection from 127.0.0.1
[2025-08-12 18:40:11] SSH login attempt from 127.0.0.1 | user: 'admin' pass: 'admin'
[2025-08-12 18:40:11] [+] Attacker 127.0.0.1 successfully logged into fake SSH shell
[2025-08-12 18:40:15] [127.0.0.1] Command: whoami
```

## Security notes - read this

- **Rotate old webhook:** a Discord webhook was hardcoded in git history (`138118...`). Delete it in Discord Channel Settings > Integrations > Webhooks, create a new one, put it only in `.env` (never commit `.env`). History rewrite (`BFG`/`filter-repo`) recommended if webhook had permissions.
- Never use real credentials for `HONEYPOT_USER/PASS`.
- Do not run on port 22 alongside real `sshd` - stop `sshd` or use redirect above.
- `ipapi.co` free tier is rate-limited (~1000/day) - failures are logged, not fatal.
- Firewall: `sudo ufw allow 2222/tcp` + decoy ports you want exposed, deny rest.
- Research / defensive use only. You are responsible for complying with local law - logging attacker IPs is threat intel, dis,intrusive actions are not.

## Troubleshooting

| Error | Fix |
|---|---|
| `Host key server_rsa.key not found` | Run `ssh-keygen` step above |
| `Permission denied on port 22` | Use `SSH_PORT=2222` or `sudo` / iptables redirect |
| `Port in use` | `sudo ss -tlnp \| grep 2222`, kill or change `SSH_PORT` |
| `Webhook alert failed 401/404` | Webhook deleted/invalid - regenerate, update `.env` |
| `GeoIP lookup failed` | `ipapi.co` limit/offline - wait, honeypot still logs |
| Docker `server_rsa.key: ro` mount missing | Generate key on host first, check path |

## Roadmap

- [ ] JSON logging + SQLite for password frequency
- [ ] Configurable fake filesystem / more commands (`pwd`, `ps`, `wget` trap)
- [ ] Rate-limit / blocklist + AbuseIPDB auto-report (opt-in)
- [ ] Prometheus metrics

## License

MIT - see [LICENSE](LICENSE).
