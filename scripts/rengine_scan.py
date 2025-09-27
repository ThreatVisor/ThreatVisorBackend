#!/usr/bin/env python3
import requests
import json
import sys

def check_security_headers(url):
    vulnerabilities = []
    try:
        response = requests.get(url, timeout=30, verify=False)
        headers = response.headers

        security_checks = [
            ('Content-Security-Policy', 'Missing Content Security Policy', 'medium'),
            ('X-Frame-Options', 'Missing X-Frame-Options Header', 'medium'),
            ('Strict-Transport-Security', 'Missing HSTS Header', 'medium'),
            ('X-Content-Type-Options', 'Missing X-Content-Type-Options Header', 'low'),
            ('Referrer-Policy', 'Missing Referrer Policy Header', 'low')
        ]

        for header, title, severity in security_checks:
            if header.lower() not in [h.lower() for h in headers.keys()]:
                vulnerabilities.append({
                    "name": title,
                    "severity": severity,
                    "description": f"The {header} security header is not configured",
                    "url": url
                })

        if 'server' in headers:
            vulnerabilities.append({
                "name": "Server Information Disclosure",
                "severity": "low",
                "description": f"Server header reveals: {headers['server']}",
                "url": url
            })

    except Exception as e:
        vulnerabilities.append({
            "name": "reNgine Scan Error",
            "severity": "info",
            "description": f"Error during security headers check: {str(e)}",
            "url": url
        })

    return vulnerabilities

target_url = "https://pranascience.com/"
vulns = check_security_headers(target_url)
result = {
    "target": target_url,
    "vulnerabilities": vulns
}

with open("/app/reports/rengine_report.json", "w") as f:
    json.dump(result, f, indent=2)

print(f"reNgine scan completed. Found {len(vulns)} issues.")
