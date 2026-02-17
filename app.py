from flask import Flask, render_template, request
import requests
import socket
import ssl
import whois

app = Flask(__name__)

def port_scan(host):
    ports = [21, 22, 80, 443]
    open_ports = []
    for port in ports:
        s = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
        s.settimeout(1)
        if s.connect_ex((host, port)) == 0:
            open_ports.append(port)
        s.close()
    return open_ports

def check_headers(url):
    try:
        response = requests.get(url, timeout=5)
        headers = response.headers
        required = [
            "Content-Security-Policy",
            "X-Frame-Options",
            "Strict-Transport-Security",
            "X-XSS-Protection"
        ]
        return [h for h in required if h not in headers]
    except:
        return ["Error checking headers"]

def check_ssl(host):
    try:
        context = ssl.create_default_context()
        with socket.create_connection((host, 443), timeout=5) as sock:
            with context.wrap_socket(sock, server_hostname=host):
                return "Valid SSL Certificate"
    except:
        return "SSL Certificate Not Valid"

def get_whois_info(domain):
    try:
        info = whois.whois(domain)
        return {
            "domain_name": info.domain_name,
            "registrar": info.registrar,
            "creation_date": info.creation_date,
            "expiry_date": info.expiration_date
        }
    except:
        return {"error": "WHOIS not available"}

@app.route("/", methods=["GET", "POST"])
def index():
    if request.method == "POST":
        url = request.form["url"]

        if not url.startswith("http"):
            url = "http://" + url

        host = url.replace("http://", "").replace("https://", "").split("/")[0]

        open_ports = port_scan(host)
        missing_headers = check_headers(url)
        ssl_status = check_ssl(host)
        whois_data = get_whois_info(host)

        risk_score = len(open_ports) * 5 + len(missing_headers) * 10
        if "Not" in ssl_status:
            risk_score += 20

        if risk_score < 20:
            risk = "Low"
        elif risk_score < 40:
            risk = "Medium"
        else:
            risk = "High"

        return render_template("result.html",
                               url=url,
                               open_ports=open_ports,
                               missing_headers=missing_headers,
                               ssl_status=ssl_status,
                               whois_data=whois_data,
                               risk=risk)

    return render_template("index.html")

if __name__ == "__main__":
    app.run(debug=True)