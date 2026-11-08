"""Lit les rapports de sécurité du build et pousse les compteurs vers le Pushgateway (tendance Grafana)."""
import json
import os
import urllib.request

PUSHGATEWAY = "http://pushgateway:9091/metrics/job/juice-shop"  # URL interne fixe (réseau devsecops)


def load(path):
    try:
        with open(path) as f:
            return json.load(f)
    except (OSError, ValueError):
        return None


metrics = {}

leaks = load("gitleaks-report.json")
metrics["devsecops_secrets_new"] = len(leaks) if isinstance(leaks, list) else 0


def trivy(path, name):
    data = load(path) or {}
    counts = {"critical": 0, "high": 0, "medium": 0, "low": 0}
    for result in data.get("Results") or []:
        for item in (result.get("Vulnerabilities") or []) + (result.get("Misconfigurations") or []):
            sev = str(item.get("Severity", "")).lower()
            if sev in counts:
                counts[sev] += 1
    for sev, n in counts.items():
        metrics[f'{name}{{severity="{sev}"}}'] = n


trivy("trivy-sca-report.json", "devsecops_sca_vulns")
trivy("trivy-image-report.json", "devsecops_image_vulns")
trivy("trivy-iac-report.json", "devsecops_iac_misconfigs")

risk_names = {"3": "high", "2": "medium", "1": "low", "0": "info"}
dast = {"high": 0, "medium": 0, "low": 0, "info": 0}
for site in (load("zap-report.json") or {}).get("site", []):
    for alert in site.get("alerts", []):
        dast[risk_names.get(str(alert.get("riskcode")), "info")] += 1
for risk, n in dast.items():
    metrics[f'devsecops_dast_alerts{{risk="{risk}"}}'] = n

metrics["devsecops_build_success"] = 1 if os.environ.get("BUILD_RESULT") == "SUCCESS" else 0
metrics["devsecops_build_number"] = int(os.environ.get("BUILD_NO", "0"))

body = "".join(f"{k} {v}\n" for k, v in metrics.items())
request = urllib.request.Request(PUSHGATEWAY, data=body.encode(), method="PUT")
urllib.request.urlopen(request, timeout=10)  # nosemgrep: URL interne constante, pas une entrée utilisateur
print(body)
