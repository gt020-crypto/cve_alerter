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
            now = datetime.now(timezone.utc)
            cutoff = now - timedelta(days=2) # 檢查最近2天
            for item in data.get("vulnerabilities", []):
                date_added = item.get("dateAdded")
                if date_added:
                    added_date = datetime.strptime(date_added, "%Y-%m-%d").replace(tzinfo=timezone.utc)
                    if added_date >= cutoff:
                        cve_id = item.get("cveID")
                        vuln_name = item.get("vulnerabilityName")
                        desc = item.get("shortDescription", "Active exploit reported by CISA KEV.")
                        vulns.append({
                            "source": "CISA KEV",
                            "id": cve_id,
                            "score": "Critical (Exploited)",
                            "desc": f"{vuln_name}: {desc}"[:300] + "...",
                            "url": f"https://nvd.nist.gov/vuln/detail/{cve_id}"
                        })
    except Exception as e:
        print(f"CISA KEV Error: {e}")
    return vulns

def check_github_advisories():
    """3. 查詢 GitHub Security Advisories 官方高危開源組件漏洞"""
    url = "https://api.github.com/advisories?severity=critical&per_page=10"
    vulns = []
    try:
        headers = {"Accept": "application/vnd.github+json"}
        res = requests.get(url, headers=headers, timeout=15)
        if res.status_code == 200:
            items = res.json()
            now = datetime.now(timezone.utc)
            cutoff = now - timedelta(hours=6)
            for item in items:
                published = item.get("published_at")
                if published:
                    pub_date = datetime.fromisoformat(published.replace("Z", "+00:00"))
                    if pub_date.tzinfo is None:
                        pub_date = pub_date.replace(tzinfo=timezone.utc)
                        
                    if pub_date >= cutoff:
                        ghsa_id = item.get("ghsa_id")
                        summary = item.get("summary", "No summary")
                        cve_id = item.get("cve_id") or ghsa_id
                        vulns.append({
                            "source": "GitHub Advisories",
                            "id": cve_id,
                            "score": "Critical (GitHub)",
                            "desc": summary[:300] + "...",
                            "url": item.get("html_url", f"https://github.com/advisories/{ghsa_id}")
                        })
    except Exception as e:
        print(f"GitHub Advisories Error: {e}")
    return vulns

def send_notification(vuln):
    """發送 Chrome 桌面通知 (透過 ntfy.sh) 與 Email"""
    # 標題改用純 ASCII 字母與數字，避免 ntfy 標題編碼錯誤
    title = f"[{vuln['source']}] Critical Vulnerability: {vuln['id']} (Score: {vuln['score']})"
    message = f"🚨 ALERT: {vuln['desc']}\n\nURL: {vuln['url']}"
    
    # 1. 發送 ntfy.sh (推送至 Chrome 桌面)
    if NTFY_TOPIC:
        try:
            requests.post(
                f"https://ntfy.sh/{NTFY_TOPIC}",
                data=message.encode('utf-8'),
                headers={
                    "Title": title,
                    "Priority": "urgent",
                    "Tags": "rotating_light,security"
                }
            )
        except Exception as e:
            print(f"Ntfy error: {e}")
            
    # 2. 發送 Email (優化 Port 587 TLS 處理)
    if EMAIL_USER and EMAIL_PASS and ALERT_TO:
        try:
            msg = MIMEMultipart()
            msg['From'] = EMAIL_USER
            msg['To'] = ALERT_TO
            msg['Subject'] = f"🚨 {title}"
            html = f"""
            <h3>{title}</h3>
            <p><b>Source:</b> {vuln['source']}</p>
            <p><b>Severity/Score:</b> {vuln['score']}</p>
            <p><b>Description:</b> {vuln['desc']}</p>
            <p><a href="{vuln['url']}" target="_blank">View Official Advisory Details</a></p>
            """
            msg.attach(MIMEText(html, 'html'))
            
            # 建立 SMTP 連線並加密發送
            server = smtplib.SMTP(SMTP_SERVER, SMTP_PORT)
            server.ehlo()
            server.starttls()
            server.ehlo()
            server.login(EMAIL_USER, EMAIL_PASS)
            server.sendmail(EMAIL_USER, ALERT_TO, msg.as_string())
            server.quit()
            print(f"Email sent successfully for {vuln['id']}")
        except Exception as e:
            print(f"Email error: {e}")

if __name__ == "__main__":
    print("Starting multi-source critical vulnerability scan...")
    all_vulns = []
    all_vulns.extend(check_nvd())
    all_vulns.extend(check_cisa_kev())
    all_vulns.extend(check_github_advisories())
    
    print(f"Found {len(all_vulns)} critical vulnerabilities across sources.")
    for v in all_vulns:
        send_notification(v)
