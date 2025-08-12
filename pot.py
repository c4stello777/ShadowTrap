import socket
import threading
import datetime
import paramiko
import signal
import sys
import requests

LOGFILE = "ssh_honeypot.log"
SSH_PORT = 22
USERNAME = "admin"
PASSWORD = "admin"
RUNNING = True  # Flag to control graceful shutdown
WEBHOOK_URL = "https://discord.com/api/webhooks/1381186649752600627/pQ-bAqTcG8_k7MqtylsymEJQTqNHB33Hd4nb6woMq9EFFH7sgCNvrnWwaHnHxlLeyIna"

# Set to track IPs already logged with geo info


seen_ips = set()

def log(msg):
    now = datetime.datetime.now().strftime("[%Y-%m-%d %H:%M:%S]")
    print(f"{now} {msg}")
    with open(LOGFILE, "a") as f:
        f.write(f"{now} {msg}\n")

def send_webhook_alert(message):
    try:
        data = {"content": message}
        response = requests.post(WEBHOOK_URL, json=data)
        if response.status_code == 204:
            log("Webhook alert sent successfully.")
        else:
            log(f"Webhook alert failed with status {response.status_code}: {response.text}")
    except Exception as e:
        log(f"Failed to send webhook alert: {e}")

def log_geoip(ip):
    if ip in seen_ips:
        return  # Already logged, skip
    seen_ips.add(ip)

    try:
        response = requests.get(f"https://ipapi.co/{ip}/json/")
        data = response.json()

        location_info = f"""
🌍 New Intrusion from IP: {ip}
- Country: {data.get('country_name', 'N/A')}
- Region: {data.get('region', 'N/A')}
- City: {data.get('city', 'N/A')}
- Org: {data.get('org', 'N/A')}
- ASN: {data.get('asn', 'N/A')}
- Latitude: {data.get('latitude', 'N/A')}
- Longitude: {data.get('longitude', 'N/A')}
- Timezone: {data.get('timezone', 'N/A')}
"""
        log(location_info.strip())
        send_webhook_alert(location_info.strip())
    except Exception as e:
        log(f"GeoIP lookup failed for {ip}: {e}")

class SSHHandler(paramiko.ServerInterface):
    def __init__(self, client_ip):
        self.client_ip = client_ip
        self.event = threading.Event()

    def check_auth_password(self, username, password):
        log(f"SSH login attempt from {self.client_ip} | user: '{username}' pass: '{password}'")
        send_webhook_alert(f"SSH Honeypot Alert: Login attempt from {self.client_ip} with user='{username}' pass='{password}'")
        if username == USERNAME and password == PASSWORD:
            return paramiko.AUTH_SUCCESSFUL
        return paramiko.AUTH_FAILED

    def get_allowed_auths(self, username):
        return "password"

    def check_channel_request(self, kind, chanid):
        if kind == "session":
            return paramiko.OPEN_SUCCEEDED
        return paramiko.OPEN_FAILED_ADMINISTRATIVELY_PROHIBITED

    def check_channel_pty_request(self, channel, term, width, height, pixelwidth, pixelheight, modes):
        return True

    def check_channel_shell_request(self, channel):
        self.event.set()
        return True

def handle_connection(client, addr):
    ip = addr[0]
    log(f"Incoming SSH connection from {ip}")
    send_webhook_alert(f"SSH Honeypot Alert: Connection from {ip}")
    log_geoip(ip)  # GeoIP info on first SSH intrusion only

    try:
        transport = paramiko.Transport(client)
        host_key = paramiko.RSAKey(filename="server_rsa.key")
        transport.add_server_key(host_key)

        server = SSHHandler(ip)
        transport.start_server(server=server)
        chan = transport.accept(20)
        if chan is None:
            log(f"SSH handshake failed from {ip}")
            return

        server.event.wait(10)
        if not server.event.is_set():
            log(f"No shell request from {ip}, closing.")
            chan.close()
            return

        log(f"[+] Attacker {ip} successfully logged into fake SSH shell")
        send_webhook_alert(f"\ud83d\udea8 SSH Honeypot Alert: Attacker `{ip}` successfully logged into the fake SSH shell using username='{USERNAME}' and password='{PASSWORD}'")

        chan.sendall("Welcome to Ubuntu 20.04.6 LTS (GNU/Linux 5.4.0-91-generic x86_64)\r\n")
        chan.sendall("You have new mail.\r\n\r\n$ ")

        buffer = ""
        while True:
            data = chan.recv(1024)
            if not data:
                break
            buffer += data.decode("utf-8", errors="ignore")
            if buffer.endswith('\n') or buffer.endswith('\r'):
                command = buffer.strip()
                log(f"[{ip}] Command: {command}")
                send_webhook_alert(f"SSH Honeypot Alert: Command from {ip}: {command}")
                buffer = ""

                if command in ["exit", "quit"]:
                    chan.sendall(f"$ {command}\r\nBye!\r\n")
                    chan.close()
                    break
                elif command == "ls":
                    chan.sendall(f"$ {command}\r\nDocuments  Downloads  Music  Pictures  Videos\r\n$ ")
                elif command == "whoami":
                    chan.sendall(f"$ {command}\r\nadmin\r\n$ ")
                elif command == "uname -a":
                    chan.sendall(f"$ {command}\r\nLinux fakebox 5.4.0-91-generic x86_64 GNU/Linux\r\n$ ")
                elif command.startswith("cat "):
                    chan.sendall(f"$ {command}\r\nPermission denied\r\n$ ")
                else:
                    chan.sendall(f"$ {command}\r\nbash: {command}: command not found\r\n$ ")

    except Exception as e:
        log(f"SSH error from {ip}: {e}")
    finally:
        client.close()

def fake_service(port, banner):
    sock = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
    sock.setsockopt(socket.SOL_SOCKET, socket.SO_REUSEADDR, 1)
    try:
        sock.bind(("0.0.0.0", port))
        sock.listen(5)
        log(f"Fake service listening on port {port}")
        while RUNNING:
            conn, addr = sock.accept()
            ip = addr[0]
            log(f"[!] Intrusion detected from {ip} on port {port}")
            log_geoip(ip)  # GeoIP info on first intrusion attempt per IP
            try:
                conn.sendall(banner.encode())
            except:
                pass
            conn.close()
    except Exception as e:
        log(f"Error on port {port}: {e}")

def start_honeypot():
    signal.signal(signal.SIGINT, shutdown)

    # Dummy services with banners
    banners = {
        21: "220 FTP Server ready.\r\n",
        23: "Welcome to fake Telnet service.\r\n",
        25: "220 fake-smtp ESMTP Postfix\r\n",
        53: "DNS query refused.\r\n",
        80: "HTTP/1.1 200 OK\r\nServer: Apache/2.4.41 (Ubuntu)\r\n\r\n",
        110: "+OK POP3 server ready\r\n",
        143: "* OK IMAP4rev1 Service Ready\r\n",
        3306: "\x00\x00\x00\x0aFakeMySQL5.5.5-10.3.29-MariaDB-0+deb10u1",
        445: "SMB negotiation failed.\r\n",
        3389: "RDP Negotiation Response Error.\r\n"
    }

    for port, banner in banners.items():
        t = threading.Thread(target=fake_service, args=(port, banner), daemon=True)
        t.start()

    # SSH honeypot
    sock = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
    sock.setsockopt(socket.SOL_SOCKET, socket.SO_REUSEADDR, 1)

    try:
        sock.bind(("0.0.0.0", SSH_PORT))
    except PermissionError:
        log(f"Permission denied on port {SSH_PORT}. Try sudo or use port >1024.")
        return
    except OSError:
        log(f"Port {SSH_PORT} in use. Stop other service or change port.")
        return

    sock.listen(100)
    log(f"SSH Honeypot started on port {SSH_PORT}")

    while RUNNING:
        try:
            client, addr = sock.accept()
            threading.Thread(target=handle_connection, args=(client, addr), daemon=True).start()
        except KeyboardInterrupt:
            break

def shutdown(sig, frame):
    global RUNNING
    RUNNING = False
    log("Shutting down honeypot...")
    sys.exit(0)

if __name__ == "__main__":
    start_honeypot()     
