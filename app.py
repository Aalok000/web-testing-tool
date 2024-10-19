from flask import Flask, render_template, request
import requests

app = Flask(__name__)

def test_sql_injection(url):
    payloads = ["'", '"', '1=1', "' OR '1'='1", "admin' --", "'; DROP TABLE users; --"]
    results = []
    for payload in payloads:
        injection_url = f"{url}?test={payload}"
        response = requests.get(injection_url)
        if "SQL syntax" in response.text or "mysql" in response.text:
            results.append(f"[!] Possible SQL Injection vulnerability detected at {injection_url}")
        else:
            results.append(f"[INFO] No SQL Injection vulnerability detected at {injection_url}")
    return "\n".join(results)

def test_xss(url):
    payloads = ["<script>alert('XSS')</script>", "<img src='x' onerror='alert(1)'>", "<svg/onload=alert('XSS')>"]
    results = []
    for payload in payloads:
        xss_url = f"{url}?test={payload}"
        response = requests.get(xss_url)
        if payload in response.text:
            results.append(f"[!] Possible XSS vulnerability detected at {xss_url}")
        else:
            results.append(f"[INFO] No XSS vulnerability detected at {xss_url}")
    return "\n".join(results)

def test_host_header_injection(url):
    payloads = ["evil.com", "localhost"]
    results = []
    for payload in payloads:
        headers = {'Host': payload}
        response = requests.get(url, headers=headers)
        if payload in response.text:
            results.append(f"[!] Possible Host Header Injection vulnerability detected with header 'Host: {payload}' at {url}")
        else:
            results.append(f"[INFO] No Host Header Injection vulnerability detected with header 'Host: {payload}' at {url}")
    return "\n".join(results)

@app.route('/', methods=['GET', 'POST'])
def index():
    if request.method == 'POST':
        url = request.form['url']
        results = []
        results.append(test_sql_injection(url))
        results.append(test_xss(url))
        results.append(test_host_header_injection(url))
        return render_template('index.html', results="\n".join(results))
    return render_template('index.html')

if __name__ == '__main__':
    app.run(debug=True)
