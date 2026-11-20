from datetime import datetime
import ipaddress
import os
import sqlite3
from urllib.parse import urlparse

from flask import Flask, jsonify, request, send_from_directory


app = Flask(__name__)
DATABASE = os.path.join(app.root_path, "autoshield.db")


def get_db():
    connection = sqlite3.connect(DATABASE)
    connection.row_factory = sqlite3.Row
    return connection


def initialize_database():
    with get_db() as connection:
        connection.execute(
            """
            CREATE TABLE IF NOT EXISTS assessments (
                id INTEGER PRIMARY KEY AUTOINCREMENT,
                date TEXT NOT NULL,
                ip TEXT NOT NULL,
                url TEXT NOT NULL,
                score INTEGER NOT NULL,
                risk TEXT NOT NULL
            )
            """
        )


def assess(ip, url, ports):
    findings = []
    recommendations = []
    risk = 0

    try:
        valid_ip = ipaddress.ip_address(ip).version == 4
    except ValueError:
        valid_ip = False

    if valid_ip:
        findings.append({
            "name": "IPv4 Validation",
            "status": "Passed",
            "level": "Low",
            "detail": "The supplied address has a valid IPv4 format.",
        })
    else:
        risk += 25
        findings.append({
            "name": "IPv4 Validation",
            "status": "Failed",
            "level": "High",
            "detail": "The supplied address is not a valid IPv4 address.",
        })
        recommendations.append("Enter a valid IPv4 address.")

    try:
        parsed = urlparse(url)
        if parsed.scheme not in ("http", "https") or not parsed.hostname:
            raise ValueError("Invalid URL")

        if parsed.scheme != "https":
            risk += 15
            findings.append({
                "name": "HTTPS Check",
                "status": "Warning",
                "level": "Medium",
                "detail": "The URL uses HTTP rather than HTTPS.",
            })
        else:
            findings.append({
                "name": "HTTPS Check",
                "status": "Passed",
                "level": "Low",
                "detail": "The URL uses the HTTPS protocol.",
            })

        try:
            ipaddress.ip_address(parsed.hostname)
            risk += 30
            findings.append({
                "name": "IP-Based URL",
                "status": "Warning",
                "level": "High",
                "detail": "The hostname is an IP address rather than a conventional domain.",
            })
        except ValueError:
            findings.append({
                "name": "Hostname Check",
                "status": "Passed",
                "level": "Low",
                "detail": "The hostname is not formatted as an IPv4 address.",
            })

        if "@" in url:
            risk += 25
            findings.append({
                "name": "URL Symbol Check",
                "status": "Warning",
                "level": "High",
                "detail": "The URL contains @, which can obscure the actual destination.",
            })

        keywords = ["login", "verify", "free-gift", "password", "account-update", "secure-login"]
        found = [word for word in keywords if word in url.lower()]
        if found:
            risk += 15
            findings.append({
                "name": "Suspicious Keywords",
                "status": "Warning",
                "level": "Medium",
                "detail": "Potentially deceptive keywords detected: " + ", ".join(found),
            })
        else:
            findings.append({
                "name": "Keyword Check",
                "status": "Passed",
                "level": "Low",
                "detail": "No configured suspicious keywords were detected.",
            })

        if len(parsed.hostname.split(".")) > 4:
            risk += 15
            findings.append({
                "name": "Subdomain Check",
                "status": "Warning",
                "level": "Medium",
                "detail": "The hostname contains an unusually large number of subdomains.",
            })
    except ValueError:
        risk += 40
        findings.append({
            "name": "URL Format",
            "status": "Invalid",
            "level": "High",
            "detail": "The supplied URL is invalid or uses an unsupported protocol.",
        })
        recommendations.append("Enter a valid HTTP or HTTPS URL.")

    port_checks = [
        ("ftp", 21, "FTP", 20, "FTP may transmit credentials without encryption."),
        ("telnet", 23, "Telnet", 25, "Telnet does not encrypt remote terminal communication."),
        ("http", 80, "HTTP", 10, "HTTP does not encrypt web traffic."),
        ("ssh", 22, "SSH", 0, "SSH provides encrypted remote access when properly configured."),
    ]

    for key, port, name, port_risk, detail in port_checks:
        enabled = ports.get(key, False) is True
        if enabled:
            risk += port_risk
            findings.append({
                "name": f"{name} (Port {port})",
                "status": "Review Needed" if port_risk else "Enabled",
                "level": "High" if port_risk >= 20 else "Medium" if port_risk else "Low",
                "detail": detail,
            })
            if port_risk:
                recommendations.append(
                    f"Review {name} on port {port} and disable it if unnecessary."
                )
        else:
            findings.append({
                "name": f"{name} (Port {port})",
                "status": "Not Selected",
                "level": "Low",
                "detail": "This service was not selected in the sample configuration.",
            })

    risk = min(risk, 100)
    score = 100 - risk
    if not recommendations:
        recommendations.append(
            "Continue using secure protocols and regularly review network configurations."
        )

    return {
        "date": datetime.now().strftime("%Y-%m-%d %H:%M:%S"),
        "ip": ip,
        "url": url,
        "score": score,
        "risk": risk,
        "findings": findings,
        "recommendations": recommendations,
    }


@app.route("/")
def index():
    return send_from_directory(app.root_path, "automatedframework.html")


@app.route("/api/assess", methods=["POST"])
def api_assess():
    data = request.get_json(silent=True) or {}
    ip = str(data.get("ip", "")).strip()
    url = str(data.get("url", "")).strip()
    ports = data.get("ports", {})

    if not ip or not url:
        return jsonify({"error": "Please enter both an IP address and a URL."}), 400
    if not isinstance(ports, dict):
        return jsonify({"error": "Ports must be provided as an object."}), 400

    report = assess(ip, url, ports)
    risk_label = "Low" if report["score"] >= 80 else "Medium" if report["score"] >= 50 else "High"

    with get_db() as connection:
        connection.execute(
            "INSERT INTO assessments (date, ip, url, score, risk) VALUES (?, ?, ?, ?, ?)",
            (report["date"], ip, url, report["score"], risk_label),
        )

    return jsonify(report)


@app.route("/api/history", methods=["GET"])
def api_history():
    with get_db() as connection:
        rows = connection.execute(
            "SELECT date, ip, score, risk FROM assessments ORDER BY id DESC LIMIT 30"
        ).fetchall()
    return jsonify([dict(row) for row in rows])


@app.route("/api/history", methods=["DELETE"])
def clear_history():
    with get_db() as connection:
        connection.execute("DELETE FROM assessments")
    return jsonify({"success": True})


initialize_database()


if __name__ == "__main__":
    app.run(debug=True)
