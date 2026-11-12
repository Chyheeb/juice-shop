#!/usr/bin/env python3
"""Génère reports/pipeline-report.html : le rapport final du pipeline envoyé par e-mail.

Une section par stage, dans l'ordre du pipeline : chemin du rapport, résumé
(compteurs par sévérité, tableau des principales vulnérabilités, extrait de log),
ou « Rapport non généré » si le stage a échoué ou a été sauté.
Bibliothèque standard uniquement (tourne dans python:3.12-alpine).
"""
import base64
import html
import json
import os
import urllib.parse
import urllib.request
from collections import Counter

BUILD_NO = os.environ.get("BUILD_NUMBER", "?")
BUILD_URL = os.environ.get("BUILD_URL", "")
JOB = os.environ.get("JOB_NAME", "juice-shop")
RESULT = os.environ.get("BUILD_RESULT", "UNKNOWN")
OUT = "reports/pipeline-report.html"
SEV_ORDER = ["CRITICAL", "HIGH", "MEDIUM", "LOW", "UNKNOWN"]
MAX_ROWS = 15
# SonarQube : URL interne (réseau Docker) pour l'API, URL publique pour les liens de l'e-mail
SONAR_API = os.environ.get("SONAR_HOST_URL", "http://sonarqube:9000").rstrip("/")
SONAR_PUBLIC = os.environ.get("SONAR_PUBLIC_URL", "http://localhost:9000").rstrip("/")
SONAR_TOKEN = os.environ.get("SONAR_AUTH_TOKEN", "")


def esc(s):
    return html.escape(str(s if s is not None else ""))


def load_json(path):
    try:
        with open(path, encoding="utf-8") as f:
            return json.load(f)
    except (OSError, ValueError):
        return None


def tail(path, n=40):
    try:
        with open(path, encoding="utf-8", errors="replace") as f:
            lines = f.read().splitlines()
    except OSError:
        return None
    return "\n".join(lines[-n:])


def table(headers, rows):
    h = "".join(f"<th>{esc(x)}</th>" for x in headers)
    b = "".join("<tr>" + "".join(f"<td>{esc(c)}</td>" for c in r) + "</tr>" for r in rows)
    return f"<table><tr>{h}</tr>{b}</table>"


def counts_line(counter):
    parts = [f"{s}={counter[s]}" for s in SEV_ORDER if counter.get(s)]
    return ", ".join(parts) if parts else "aucune"


def sort_sev(rows, idx=0):
    return sorted(rows, key=lambda r: SEV_ORDER.index(r[idx]) if r[idx] in SEV_ORDER else 9)


# ---------- résumés par outil ----------

def gitleaks(path):
    data = load_json(path)
    if data is None:
        return None
    rows = [(d.get("RuleID"), d.get("File"), d.get("StartLine"), d.get("Description")) for d in data]
    out = f"<p><b>Nouveaux secrets détectés : {len(rows)}</b> (hors baseline de 202 secrets connus)</p>"
    if rows:
        out += table(["Règle", "Fichier", "Ligne", "Description"], rows[:MAX_ROWS])
    return out


def sonar_get(endpoint, params):
    """Appel GET à l'API SonarQube ; None en cas d'erreur (le rapport ne doit jamais casser)."""
    url = f"{SONAR_API}{endpoint}?{urllib.parse.urlencode(params)}"
    req = urllib.request.Request(url)
    if SONAR_TOKEN:
        auth = base64.b64encode(f"{SONAR_TOKEN}:".encode()).decode()
        req.add_header("Authorization", f"Basic {auth}")
    try:
        with urllib.request.urlopen(req, timeout=15) as r:
            return json.load(r)
    except Exception as e:  # noqa: BLE001
        print(f"API SonarQube indisponible ({endpoint}) : {e}")
        return None


def sonar_project_key():
    rt = tail(".scannerwork/report-task.txt", 50) or ""
    for line in rt.splitlines():
        if line.startswith("projectKey="):
            return line.split("=", 1)[1].strip()
    return None


def issue_severity(i):
    for imp in i.get("impacts") or []:
        if imp.get("softwareQuality") == "SECURITY":
            return imp.get("severity", "")
    return i.get("severity", "")


def sonar(path):
    txt = tail(path)
    if txt is None:
        return None
    out = f"<p><b>{esc(txt.strip())}</b></p>"
    key = sonar_project_key()
    if not key:
        return out
    q = urllib.parse.quote(key)
    dash = f"{SONAR_PUBLIC}/dashboard?id={q}"
    vulns_url = f"{SONAR_PUBLIC}/project/issues?id={q}&impactSoftwareQualities=SECURITY&resolved=false"
    hot_url = f"{SONAR_PUBLIC}/security_hotspots?id={q}"
    out += (f'<p><a href="{esc(dash)}">Tableau de bord SonarQube</a> · '
            f'<a href="{esc(vulns_url)}">Vulnérabilités</a> · '
            f'<a href="{esc(hot_url)}">Security hotspots</a></p>')

    m = sonar_get("/api/measures/component", {"component": key,
                  "metricKeys": "vulnerabilities,security_hotspots,bugs,code_smells,security_rating"})
    if m and m.get("component"):
        vals = {x["metric"]: x.get("value", "—") for x in m["component"].get("measures", [])}
        rating = {"1.0": "A", "2.0": "B", "3.0": "C", "4.0": "D", "5.0": "E"}
        out += table(["Vulnérabilités", "Security hotspots", "Bugs", "Code smells", "Note sécurité"],
                     [(vals.get("vulnerabilities", "—"), vals.get("security_hotspots", "—"),
                       vals.get("bugs", "—"), vals.get("code_smells", "—"),
                       rating.get(vals.get("security_rating", ""), vals.get("security_rating", "—")))])

    iss = sonar_get("/api/issues/search", {"componentKeys": key, "impactSoftwareQualities": "SECURITY",
                                           "resolved": "false", "ps": MAX_ROWS})
    if iss is not None:
        rows = []
        for i in iss.get("issues", []):
            comp = i.get("component", "").split(":", 1)[-1]
            rows.append((issue_severity(i), i.get("rule"), comp, i.get("line", "—"), i.get("message")))
        out += f"<p><b>Problèmes de sécurité ouverts : {iss.get('total', len(rows))}</b></p>"
        if rows:
            out += table(["Sévérité", "Règle", "Fichier", "Ligne", "Message"], rows)

    hs = sonar_get("/api/hotspots/search", {"projectKey": key, "status": "TO_REVIEW", "ps": MAX_ROWS})
    if hs is not None:
        rows = [(h.get("vulnerabilityProbability"), h.get("securityCategory"),
                 h.get("component", "").split(":", 1)[-1], h.get("line", "—"), h.get("message"))
                for h in hs.get("hotspots", [])]
        total = (hs.get("paging") or {}).get("total", len(rows))
        out += f"<p><b>Security hotspots à revoir : {total}</b></p>"
        if rows:
            out += table(["Probabilité", "Catégorie", "Fichier", "Ligne", "Message"], rows)
    return out


def trivy_vuln(path, label):
    data = load_json(path)
    if data is None:
        return None
    c, rows = Counter(), []
    for r in data.get("Results") or []:
        for v in r.get("Vulnerabilities") or []:
            c[v.get("Severity", "UNKNOWN")] += 1
            rows.append((v.get("Severity"), v.get("VulnerabilityID"), v.get("PkgName"),
                         v.get("InstalledVersion"), v.get("FixedVersion") or "—"))
    out = f"<p><b>{label} par sévérité : {counts_line(c)}</b></p>"
    if rows:
        out += "<p>Principales vulnérabilités :</p>"
        out += table(["Sévérité", "CVE", "Paquet", "Installée", "Corrigée"], sort_sev(rows)[:MAX_ROWS])
    return out


def trivy_iac(path):
    data = load_json(path)
    if data is None:
        return None
    c, rows = Counter(), []
    for r in data.get("Results") or []:
        for m in r.get("Misconfigurations") or []:
            c[m.get("Severity", "UNKNOWN")] += 1
            rows.append((m.get("Severity"), m.get("ID"), r.get("Target"), m.get("Title")))
    out = f"<p><b>Mauvaises configurations par sévérité : {counts_line(c)}</b></p>"
    if rows:
        out += table(["Sévérité", "Règle", "Fichier", "Problème"], sort_sev(rows)[:MAX_ROWS])
    return out


def zap(path):
    data = load_json(path)
    if data is None:
        return None
    risk = {"3": "HIGH", "2": "MEDIUM", "1": "LOW", "0": "INFO"}
    c, rows = Counter(), []
    for site in data.get("site") or []:
        for a in site.get("alerts") or []:
            lvl = risk.get(str(a.get("riskcode")), "UNKNOWN")
            c[lvl] += 1
            rows.append((lvl, a.get("pluginid"), a.get("name"), len(a.get("instances") or [])))
    order = ["HIGH", "MEDIUM", "LOW", "INFO"]
    line = ", ".join(f"{k}={c[k]}" for k in order if c.get(k)) or "aucune"
    out = f"<p><b>Alertes par risque : {line}</b></p>"
    if rows:
        rows.sort(key=lambda r: order.index(r[0]) if r[0] in order else 9)
        out += table(["Risque", "Règle", "Alerte", "Occurrences"], rows[:MAX_ROWS])
    return out


def logfile(path, n=40):
    txt = tail(path, n)
    if txt is None:
        return None
    return f"<pre>{esc(txt)}</pre>"


def sbom(path):
    data = load_json(path)
    if data is None:
        return None
    n = len(data.get("components") or [])
    return f"<p><b>SBOM CycloneDX : {n} composants</b></p>"


# ---------- assemblage ----------

STAGES = [
    ("Secrets scan — Gitleaks", "gitleaks-report.json", lambda p: gitleaks(p)),
    ("SAST — SonarQube / Quality Gate", "reports/sonar-quality-gate.txt", lambda p: sonar(p)),
    ("IaC scan — Trivy", "trivy-iac-report.json", lambda p: trivy_iac(p)),
    ("Build & Unit tests", "reports/build-test.log", lambda p: logfile(p, 25)),
    ("SBOM", "frontend/dist/bom/bom.json", lambda p: sbom(p)),
    ("SCA — Trivy (dépendances)", "trivy-sca-report.json", lambda p: trivy_vuln(p, "Vulnérabilités")),
    ("Docker build", "reports/docker-build.log", lambda p: logfile(p, 25)),
    ("Image scan — Trivy", "trivy-image-report.json", lambda p: trivy_vuln(p, "Vulnérabilités de l'image")),
    ("DAST — OWASP ZAP", "zap-report.json", lambda p: zap(p)),
    ("Deploy (staging)", "reports/deploy.log", lambda p: logfile(p, 15)),
]

color = "#1a7f37" if RESULT == "SUCCESS" else "#c62828"
parts = [f"""<html><head><meta charset="utf-8"><style>
body{{font-family:Arial,sans-serif;font-size:14px;color:#222}}
h1{{color:#1f5fbf}} h2{{border-top:1px solid #ccc;padding-top:10px;margin-top:24px}}
table{{border-collapse:collapse;font-size:12px}} th,td{{border:1px solid #bbb;padding:3px 6px;text-align:left}}
th{{background:#eee}} pre{{background:#f4f4f4;padding:8px;font-size:11px;overflow:auto}}
.missing{{color:#888;font-style:italic}}
</style></head><body>
<h1>DevSecOps — Rapport final du pipeline</h1>
<p><b>Projet :</b> {esc(JOB)}<br>
<b>Build :</b> #{esc(BUILD_NO)}<br>
<b>Statut global :</b> <span style="color:{color};font-weight:bold">{esc(RESULT)}</span></p>
<p><a href="{esc(BUILD_URL)}">Ouvrir le build Jenkins</a> ·
<a href="{esc(BUILD_URL)}artifact/">Artefacts</a></p>
<h2>Rapports détaillés</h2>"""]

for title, path, fn in STAGES:
    parts.append(f"<h2>{esc(title)}</h2><p><b>Rapport :</b> {esc(path)}</p>")
    body = fn(path) if os.path.exists(path) else None
    parts.append(body if body is not None
                 else '<p class="missing">Rapport non généré (étape en échec ou sautée).</p>')

parts.append("""<h2>Pièces jointes</h2>
<p>Tous les rapports disponibles sont joints à cet e-mail (JSON, logs, SBOM).</p>
<p style="color:#888;font-size:12px">E-mail généré automatiquement par Jenkins — pipeline DevSecOps juice-shop.</p>
</body></html>""")

os.makedirs("reports", exist_ok=True)
with open(OUT, "w", encoding="utf-8") as f:
    f.write("\n".join(parts))
print(f"Rapport écrit : {OUT}")