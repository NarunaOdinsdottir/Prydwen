#!/usr/bin/env python3
# ───────────────────────────────────────────────
#   ⚙️ PROJECT: PRYDWEN LOG WATCHER
#   Brotherhood of Steel - Data Integrity Division
#   Version 1.2 - Diagnostic Terminal Edition
# ───────────────────────────────────────────────

import re
import time
import os
import sys
import smtplib
import logging
import random
import psutil  # für Systemstatus
from email.message import EmailMessage
from collections import deque
from watchdog.observers import Observer
from watchdog.events import FileSystemEventHandler
from datetime import datetime
import yaml

try:
    from plyer import notification
except ImportError:
    notification = None

try:
    from colorama import Fore, Style, init
    init(autoreset=True)
except ImportError:
    class DummyColor:
        RESET = ''
        RED = ''
        GREEN = ''
        CYAN = ''
        YELLOW = ''
        MAGENTA = ''
        BLUE = ''
        WHITE = ''
        BRIGHT = ''
    Fore = Style = DummyColor()

# ───────────────────────────────────────────────
#   🧱 Brotherhood Banner
# ───────────────────────────────────────────────
def banner():
    print(Fore.CYAN + Style.BRIGHT + r"""
   ┌──────────────────────────────────────────┐
   │     BROTHERHOOD OF STEEL - DIVISION      │
   │        ⚙️  PRYDWEN SYSTEM WATCHER ⚙️     │
   │     Protecting Knowledge Since 2161      │
   └──────────────────────────────────────────┘
      """ + Style.RESET)

# ───────────────────────────────────────────────
#   ⚙️ Logging Setup
# ───────────────────────────────────────────────
logging.basicConfig(
    filename="prydwen_runtime.log",
    level=logging.INFO,
    format="%(asctime)s - %(levelname)s - %(message)s"
)

DEFAULT_CONFIG = {
    "logs": ["/var/log/auth.log"],
    "patterns": {
        "failed_login": r"(Failed password|authentication failure|invalid user)",
        "sudo_failed": r"sudo: .*authentication failure",
        "ssh_closed": r"Connection closed by",
        "sql_error": r"(SQL syntax error|mysql)",
        "cmd_injection": r"(;|\||`).*rm -rf"
    },
    "thresholds": {
        "failed_login": {"count": 5, "window_seconds": 60}
    },
    "whitelist_ips": [],
    "notify": {
        "desktop": True,
        "email": False,
        "email_config": {
            "smtp_server": "smtp.example.com",
            "smtp_port": 587,
            "username": "you@example.com",
            "password": "",
            "to": ["you@example.com"]
        }
    }
}

# ───────────────────────────────────────────────
#   📜 Config Loader
# ───────────────────────────────────────────────
def load_config(path):
    cfg = DEFAULT_CONFIG.copy()
    if not path or not os.path.exists(path):
        print(Fore.YELLOW + "⚠ Keine Konfiguration gefunden. Standardprotokolle werden geladen.")
        logging.warning("No config found - using default Brotherhood directives.")
        return cfg
    with open(path, "r") as f:
        user_cfg = yaml.safe_load(f) or {}
        cfg.update(user_cfg)
    print(Fore.GREEN + "✓ Konfiguration erfolgreich geladen.")
    return cfg

# ───────────────────────────────────────────────
#   🔔 Alert-Systeme
# ───────────────────────────────────────────────
def desktop_alert(title, message):
    if notification:
        try:
            notification.notify(title=title, message=message, timeout=8)
        except Exception as e:
            logging.exception(f"Desktop notification failed: {e}")

def email_alert(cfg_email, subject, body):
    try:
        msg = EmailMessage()
        msg["Subject"] = subject
        msg["From"] = cfg_email["username"]
        msg["To"] = ", ".join(cfg_email["to"])
        msg.set_content(body)
        with smtplib.SMTP(cfg_email["smtp_server"], cfg_email["smtp_port"], timeout=10) as s:
            s.starttls()
            s.login(cfg_email["username"], cfg_email.get("password", ""))
            s.send_message(msg)
        logging.info(f"Email alert sent: {subject}")
    except Exception as e:
        logging.exception(f"Failed to send email alert: {e}")

# ───────────────────────────────────────────────
#   ⏱ Rate Limiter
# ───────────────────────────────────────────────
class RateLimiter:
    def __init__(self, count, window_seconds):
        self.count = count
        self.window = window_seconds
        self.events = deque()

    def add_event(self, ts):
        self.events.append(ts)
        while self.events and (ts - self.events[0]) > self.window:
            self.events.popleft()
        return len(self.events) >= self.count

# ───────────────────────────────────────────────
#   🧩 Log Handler
# ───────────────────────────────────────────────
def extract_ip(line):
    m = re.search(r"(\d{1,3}(?:\.\d{1,3}){3})", line)
    return m.group(1) if m else None

class LogHandler(FileSystemEventHandler):
    def __init__(self, path, patterns, trackers, cfg):
        self.path = path
        self.f = open(path, "r", errors="ignore")
        self.f.seek(0, os.SEEK_END)
        self.patterns = [(name, re.compile(pat, re.IGNORECASE)) for name, pat in patterns.items()]
        self.trackers = trackers
        self.cfg = cfg

    def on_modified(self, event):
        if event.src_path != self.path:
            return
        for line in self.f:
            self.process_line(line.strip())

    def process_line(self, line):
        if not line:
            return
        for name, regex in self.patterns:
            if regex.search(line):
                ip = extract_ip(line)
                if ip and ip in self.cfg.get("whitelist_ips", []):
                    print(Fore.CYAN + f"🛡 Whitelisted IP {ip} – Ignoriert.")
                    return

                tcfg = self.cfg.get("thresholds", {}).get(name)
                if tcfg:
                    tracker = self.trackers[name]
                    if tracker.add_event(time.time()):
                        msg = (f"⚠ Threshold erreicht für {name}:"
                               f"{tcfg['count']} Ereignisse in {tcfg['window_seconds']}s.\nBeispiel: {line}")
                        self.trigger_alert(name, msg, color=Fore.RED)
                        return
                else:
                    msg = f"Verdächtiges Muster [{name}]: {line}"
                    self.trigger_alert(name, msg, color=Fore.YELLOW)

    def trigger_alert(self, name, msg, color=Fore.RED):
        title = f"⚔ Brotherhood Alert: {name}"
        print(color + f"\n{title}\n{msg}\n" + Style.RESET_ALL)
        logging.warning(f"[{title}] {msg}")
        if self.cfg.get("notify", {}).get("desktop", True):
            desktop_alert(title, msg[:200])
        if self.cfg.get("notify", {}).get("email", False):
            email_alert(self.cfg["notify"]["email_config"], title, msg)

# ───────────────────────────────────────────────
#   🧠 MINI STATUSKONSOLE
# ───────────────────────────────────────────────
BROTHERHOOD_QUOTES = [
    "„Technologie ist die Fackel, die die Menschheit aus der Dunkelheit führt.“",
    "„Steel be my body, and data my soul.“",
    "„Nur Wissen ist Macht – und wir sind seine Hüter.“",
    "„Fehlerhafte Logins? Ketzer an der Datenfront!“",
    "„Vertraue niemals einem ungesicherten Port.“"
]

def status_console(active_handlers):
    cpu = psutil.cpu_percent()
    mem = psutil.virtual_memory().percent
    net = "online" if any([s.isup for s in psutil.net_if_stats().values()]) else "offline"
    quote = random.choice(BROTHERHOOD_QUOTES) if BROTHERHOOD_QUOTES else "Stay vigilant."

    print(Fore.BLUE + "──────────────── SYSTEM STATUS ────────────────")
    print(Fore.CYAN + f"CPU-Auslastung:   {cpu}%")
    print(Fore.CYAN + f"RAM-Auslastung:   {mem}%")
    print(Fore.CYAN + f"Netzwerkstatus:   {net}")
    print(Fore.CYAN + f"Aktive Überw.:    {len(active_handlers)} Datei(en)")
    print(Fore.YELLOW + f"Spruch des Tages: {quote}")
    print(Fore.BLUE + "───────────────────────────────────────────────\n" + Style.RESET)
# ───────────────────────────────────────────────
#   🧩 MAIN
# ───────────────────────────────────────────────
def main(cfg_path=None):
    banner()
    print(Fore.MAGENTA + "🛰 Initializing PRYDWEN Diagnostic Terminal...\n")

    # 🔹 Config laden
    cfg = load_config(cfg_path)

    # 🔹 Threshold Tracker vorbereiten
    trackers = {name: RateLimiter(tcfg["count"], tcfg["window_seconds"])
                for name, tcfg in cfg.get("thresholds", {}).items()}

    # Default Tracker für Muster ohne Threshold
    for name in cfg.get("patterns", {}).keys():
        trackers.setdefault(name, RateLimiter(999999, 60))

    # 🔹 Observer und LogHandler vorbereiten
    observer = Observer()
    handlers = []
    for log_path in cfg.get("logs", []):
        if not os.path.exists(log_path):
            print(Fore.YELLOW + f"⚠ Log-Datei {log_path} nicht gefunden – übersprungen.")
            continue
        handler = LogHandler(log_path, cfg["patterns"], trackers, cfg)
        observer.schedule(handler, os.path.dirname(log_path) or ".", recursive=False)
        handlers.append(handler)
        print(Fore.GREEN + f"📡 Überwachung aktiviert für: {log_path}")

    if not handlers:
        print(Fore.RED + "❌ Keine gültigen Log-Dateien gefunden. Mission abgebrochen.")
        return

    # 🔹 PRYDWEN Online
    observer.start()
    print(Fore.CYAN + "\n✅ PRYDWEN ONLINE. Standing by for hostiles...\n")

    try:
        tick = 0
        while True:
            time.sleep(1)
            tick += 1
            # Alle 10 Sekunden Statuskonsole anzeigen
            if tick % 10 == 0:
                status_console(handlers)

    except KeyboardInterrupt:
        print(Fore.YELLOW + "\n🛑 Mission abgebrochen – Systemabschaltung eingeleitet.")
        observer.stop()
    observer.join()

if __name__ == "__main__":
    cfg = sys.argv[1] if len(sys.argv) > 1 else None
    main(cfg)
