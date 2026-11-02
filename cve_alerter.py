import os
import requests
import smtplib
from email.mime.text import MIMEText
from email.mime.multipart import MIMEMultipart
from datetime import datetime, timezone, timedelta

# 環境變數設定
NTFY_TOPIC = os.environ.get("NTFY_TOPIC")
SMTP_SERVER = os.environ.get("SMTP_SERVER", "smtp.gmail.com")
SMTP_PORT = int(os.environ.get("SMTP_PORT", 587))
EMAIL_USER = os.environ.get("EMAIL_USER")
EMAIL_PASS = os.environ.get("EMAIL_PASS")
ALERT_TO = os.environ.get("ALERT_TO")

def check_nvd():
    """1. 查詢 NIST NVD 官方 CVSS >= 9.0 (CRITICAL) 漏洞"""
    url = "https://services.nvd.nist.gov/rest/json/cves/2.0?cvssV3Severity=CRITICAL"
    vulns = []
    try:
        res = requests.get(url, timeout=15)
        if res.status_code == 200:
            data = res.json()
            now = datetime.now(timezone.utc)
            cutoff = now - timedelta(hours=6) # 檢查近6小時內發布
            for item in data.get("vulnerabilities", []):
                cve = item.get("cve", {})
                cve_id = cve.get("id")
                published = cve.get("published")
                if published:
                    pub_date = datetime.fromisoformat(published.replace("Z", "+00:00"))
                    # 確保兩者皆具備時區屬性 (Timezone-aware)
                    if pub_date.tzinfo is None:
                        pub_date = pub_date.replace(tzinfo=timezone.utc)
                        
                    if pub_date >= cutoff:
                        metrics = cve.get("metrics", {})
                        score = "N/A"
                        for k in ["cvssMetricV31", "cvssMetricV30"]:
                            if k in metrics:
                                score = metrics[k][0]["cvssData"]["baseScore"]
                                break
                        if isinstance(score, (int, float)) and score >= 9.0:
                            desc = cve.get("descriptions", [{}])[0].get("value", "No description")
                            vulns.append({
                                "source": "NIST NVD",
                                "id": cve_id,
                                "score": score,
                                "desc": desc[:300] + "...",
                                "url": f"https://nvd.nist.gov/vuln/detail/{cve_id}"
                            })
    except Exception as e:
        print(f"NVD Error: {e}")
    return vulns

def check_cisa_kev():
    """2. 查詢 CISA KEV (已遭實際利用的重大漏洞)"""
    url = "https://www.cisa.gov/sites/default/files/feeds/known_exploited_vulnerabilities.json"
    vulns = []
    try:
        res = requests.get(url, timeout=15)
        if res.status_code == 200:
            data = res.json()
            now = datetime.now
