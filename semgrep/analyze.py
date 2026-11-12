"""
analyze.py — Agrega los resultados JSON de Semgrep (3 proyectos de bWAPP),
calcula la postura de seguridad y genera las gráficas del laboratorio.

Uso (desde la raíz del laboratorio):
    python semgrep/analyze.py                 # lee semgrep/out/{core,admin,soap}.json
    python semgrep/analyze.py --in otra/ruta  # otra carpeta de entrada

Salidas:
    semgrep/summary.json     conteos por proyecto, severidad, OWASP, tipo, archivo
    semgrep/findings.json    lista completa de hallazgos (con fragmento de código)
    semgrep/findings.csv     lo mismo en CSV (para Excel)
    charts/01..05_*.png      las 5 gráficas
"""
import argparse
import collections
import csv
import datetime as dt
import json
import os
import subprocess

import matplotlib

matplotlib.use("Agg")
import matplotlib.pyplot as plt  # noqa: E402

ROOT = os.path.dirname(os.path.dirname(os.path.abspath(__file__)))
PROJECTS = [
    ("core", "Core bWAPP", "app/ (sin admin ni soap)", "Aplicación vulnerable principal"),
    ("admin", "admin", "app/admin/", "Panel de administración"),
    ("soap", "soap (NuSOAP)", "app/soap/", "Librería de servicios web (tercero)"),
]
SEV_MAP = {"ERROR": "Alta", "WARNING": "Media", "INFO": "Baja"}
SEV_ORDER = ["Alta", "Media", "Baja"]
WEIGHT = {"Alta": 5, "Media": 3, "Baja": 1}
RCE_CLASSES = {"Command Injection", "Code Injection (eval)", "File Inclusion (LFI/RFI)"}
TAINT_RULES = {
    "php-sql-injection", "php-command-injection", "php-code-injection-eval",
    "php-reflected-xss", "php-file-inclusion", "php-ldap-injection",
    "php-mail-injection", "php-open-redirect", "php-path-traversal",
}

# Paleta (dataviz): estado para severidad, slot 1 para series únicas.
C = {
    "surface": "#fcfcfb", "ink": "#0b0b0b", "ink2": "#52514e", "muted": "#898781",
    "grid": "#e1e0d9", "axis": "#c3c2b7", "series": "#2a78d6",
    "Alta": "#d03b3b", "Media": "#ec835a", "Baja": "#fab219",
}
plt.rcParams.update({
    "font.family": ["Segoe UI", "DejaVu Sans", "sans-serif"],
    "font.size": 11,
    "axes.facecolor": C["surface"], "figure.facecolor": C["surface"],
    "axes.edgecolor": C["axis"], "axes.labelcolor": C["ink2"],
    "xtick.color": C["muted"], "ytick.color": C["ink"],
    "axes.spines.top": False, "axes.spines.right": False,
})


# --------------------------------------------------------------------------- #
def rule_id(check_id):
    return check_id.split(".")[-1]


def read_source(rel_path):
    """Lee el archivo fuente; si está bloqueado (antivirus), lo toma de git."""
    full = os.path.join(ROOT, rel_path)
    try:
        with open(full, encoding="latin-1") as fh:
            return fh.read().splitlines(), "disco"
    except OSError:
        repo = os.path.join(ROOT, "bWAPP")
        inner = os.path.relpath(full, repo).replace("\\", "/")
        try:
            out = subprocess.run(
                ["git", "-C", repo, "show", f"HEAD:{inner}"],
                capture_output=True, check=True,
            ).stdout.decode("latin-1")
            return out.splitlines(), "git"
        except Exception:  # noqa: BLE001
            return [], "no disponible"


_cache = {}


def snippet(rel_path, start, end, col=1):
    if rel_path not in _cache:
        _cache[rel_path] = read_source(rel_path)
    lines, origin = _cache[rel_path]
    first = lines[start - 1] if start - 1 < len(lines) else ""
    if len(first) > 220:  # línea muy larga (código minificado): ventana alrededor del hallazgo
        a = max(0, col - 90)
        text = ("… " if a else "") + first[a:col + 110].strip() + " …"
        return text, origin
    chunk = [ln.strip() for ln in lines[start - 1:min(end, start + 2)]]
    text = " ".join(x for x in chunk if x)
    return (text[:280] + " …") if len(text) > 280 else text, origin


def fkey(r_or_f):
    """Clave estable de un hallazgo: (archivo, línea, columna, regla)."""
    if "check_id" in r_or_f:
        return (r_or_f["path"].replace("\\", "/").split("bWAPP/", 1)[-1], r_or_f["start"]["line"],
                r_or_f["start"]["col"], rule_id(r_or_f["check_id"]))
    return (r_or_f["file"], r_or_f["line"], r_or_f["col"], r_or_f["rule"])


def load_extra(path):
    """Hallazgos de las reglas taint nuevas (punto extra)."""
    if not os.path.exists(path):
        return []
    with open(path, encoding="utf-8") as fh:
        data = json.load(fh)
    out = []
    for r in data["results"]:
        rel = r["path"].replace("\\", "/")
        md = r["extra"].get("metadata", {})
        code, origin = snippet(rel, r["start"]["line"], r["end"]["line"], r["start"]["col"])
        out.append({
            "id": "", "rule": rule_id(r["check_id"]), "vuln_class": md.get("vuln_class"),
            "owasp": md.get("owasp"), "cwe": md.get("cwe"),
            "severity": SEV_MAP.get(r["extra"]["severity"], "Baja"),
            "file": rel.split("bWAPP/", 1)[-1], "line": r["start"]["line"], "col": r["start"]["col"],
            "snippet": code, "snippet_origin": origin,
            "remediation": " ".join(str(md.get("remediation", "")).split()),
        })
    out.sort(key=lambda f: (f["rule"], f["file"], f["line"]))
    for i, f in enumerate(out, 1):
        f["id"] = f"X-{i:02d}"
    return out


def load_v2(in_dir):
    """Claves y conteos del re-escaneo con el ruleset ajustado (T6)."""
    keys, counts = set(), collections.Counter()
    for key, *_ in PROJECTS:
        path = os.path.join(in_dir, "v2", f"{key}.json")
        if not os.path.exists(path):
            return None, None
        with open(path, encoding="utf-8") as fh:
            for r in json.load(fh)["results"]:
                keys.add(fkey(r))
                counts[rule_id(r["check_id"])] += 1
    return keys, counts


def load(in_dir):
    findings, meta = [], {}
    for key, name, folder, role in PROJECTS:
        path = os.path.join(in_dir, f"{key}.json")
        with open(path, encoding="utf-8") as fh:
            data = json.load(fh)
        scanned = data.get("paths", {}).get("scanned", [])
        meta[key] = {
            "name": name, "folder": folder, "role": role,
            "files": len(scanned), "errors": len(data.get("errors", [])),
            "version": data.get("version"),
        }
        for r in data["results"]:
            rel = r["path"].replace("\\", "/")
            md = r["extra"].get("metadata", {})
            sev = SEV_MAP.get(r["extra"]["severity"], "Baja")
            code, origin = snippet(rel, r["start"]["line"], r["end"]["line"], r["start"]["col"])
            rid = rule_id(r["check_id"])
            findings.append({
                "project": key,
                "rule": rid,
                "mode": "taint" if rid in TAINT_RULES else "patrón",
                "vuln_class": md.get("vuln_class", rid),
                "owasp": md.get("owasp", "N/D"),
                "cwe": md.get("cwe", "N/D"),
                "severity": sev,
                "file": rel.split("bWAPP/", 1)[-1],
                "line": r["start"]["line"],
                "col": r["start"]["col"],
                "snippet": code,
                "snippet_origin": origin,
                "message": " ".join(r["extra"]["message"].split()),
                "remediation": md.get("remediation", ""),
            })
    findings.sort(key=lambda f: (PROJECTS.index(next(p for p in PROJECTS if p[0] == f["project"])),
                                 SEV_ORDER.index(f["severity"]), f["file"], f["line"]))
    for i, f in enumerate(findings, 1):
        f["id"] = f"F-{i:03d}"
    return findings, meta


def posture(by_sev, classes):
    alta = by_sev.get("Alta", 0)
    if (alta and classes & RCE_CLASSES) or alta >= 10:
        return "Crítica"
    if alta:
        return "Alta"
    if by_sev.get("Media", 0):
        return "Media"
    return "Baja"


def summarize(findings, meta):
    cnt = lambda key, items: collections.Counter(f[key] for f in items)  # noqa: E731
    per_project = {}
    for key, *_ in PROJECTS:
        items = [f for f in findings if f["project"] == key]
        by_sev = cnt("severity", items)
        classes = set(f["vuln_class"] for f in items)
        risk = sum(WEIGHT[s] * n for s, n in by_sev.items())
        per_project[key] = {
            **meta[key],
            "findings": len(items),
            "by_severity": {s: by_sev.get(s, 0) for s in SEV_ORDER},
            "by_class": dict(cnt("vuln_class", items).most_common()),
            "risk_index": risk,
            "posture": posture(by_sev, classes),
        }
    by_sev = cnt("severity", findings)
    core_items = [f for f in findings if f["project"] == "core"]
    top_files = []
    for fname, n in cnt("file", core_items).most_common(10):
        sev = cnt("severity", [f for f in core_items if f["file"] == fname])
        top_files.append({"file": fname, "total": n,
                          "by_severity": {s: sev.get(s, 0) for s in SEV_ORDER}})
    total_files = sum(m["files"] for m in meta.values())
    risk = sum(WEIGHT[s] * n for s, n in by_sev.items())
    return {
        "generated": dt.datetime.now().isoformat(timespec="seconds"),
        "semgrep_version": next(iter(meta.values()))["version"],
        "ruleset": "semgrep/php-sast-rules.yml (14 reglas)",
        "repository": "https://github.com/raesene/bWAPP",
        "totals": {
            "findings": len(findings),
            "files_scanned": total_files,
            "risk_index": risk,
            "risk_per_file": round(risk / total_files, 2) if total_files else 0,
            "by_severity": {s: by_sev.get(s, 0) for s in SEV_ORDER},
            "taint_findings": sum(1 for f in findings if f["mode"] == "taint"),
            "pattern_findings": sum(1 for f in findings if f["mode"] == "patrón"),
        },
        "per_project": per_project,
        "by_owasp": dict(cnt("owasp", findings).most_common()),
        "by_class": dict(cnt("vuln_class", findings).most_common()),
        "by_rule": dict(cnt("rule", findings).most_common()),
        "by_cwe": dict(cnt("cwe", findings).most_common()),
        "top_files_core": top_files,
    }


# --------------------------------------------------------------------------- #
def _finish(ax, fig, title, subtitle, path):
    ax.set_title(title, loc="left", fontsize=15, fontweight="bold", color=C["ink"], pad=26)
    ax.text(0, 1.02, subtitle, transform=ax.transAxes, fontsize=10.5, color=C["ink2"], va="bottom")
    ax.xaxis.grid(True, color=C["grid"], linewidth=0.8)
    ax.set_axisbelow(True)
    ax.tick_params(axis="y", length=0)
    ax.spines["left"].set_visible(False)
    fig.text(0.99, 0.01, "Fuente: Semgrep 1.185 · php-sast-rules.yml · raesene/bWAPP",
             ha="right", fontsize=8.5, color=C["muted"])
    fig.tight_layout()
    fig.savefig(path, dpi=160)
    plt.close(fig)


def hbar(labels, values, title, subtitle, path, total=None):
    fig, ax = plt.subplots(figsize=(10, 0.5 * len(labels) + 1.9))
    y = range(len(labels))[::-1]
    ax.barh(list(y), values, height=0.62, color=C["series"], edgecolor=C["surface"], linewidth=1.5)
    ax.set_yticks(list(y), labels)
    vmax = max(values)
    for yi, v in zip(y, values):
        pct = f"  ({v / total:.0%})" if total else ""
        ax.text(v + vmax * 0.01, yi, f"{v}{pct}", va="center", fontsize=10, color=C["ink"])
    ax.set_xlim(0, vmax * 1.18)
    _finish(ax, fig, title, subtitle, path)


def stacked(labels, rows, title, subtitle, path):
    """rows: lista de dicts {Alta, Media, Baja}"""
    fig, ax = plt.subplots(figsize=(10, 0.55 * len(labels) + 2.1))
    y = list(range(len(labels)))[::-1]
    left = [0] * len(labels)
    for sev in SEV_ORDER:
        vals = [r.get(sev, 0) for r in rows]
        ax.barh(y, vals, left=left, height=0.62, color=C[sev], edgecolor=C["surface"],
                linewidth=1.5, label=sev)
        left = [a + b for a, b in zip(left, vals)]
    ax.set_yticks(y, labels)
    vmax = max(left)
    for yi, tot in zip(y, left):
        ax.text(tot + vmax * 0.01, yi, str(tot), va="center", fontsize=10, color=C["ink"], fontweight="bold")
    ax.set_xlim(0, vmax * 1.12)
    ax.legend(title="Severidad", frameon=False, loc="lower right", fontsize=9.5, title_fontsize=9.5)
    _finish(ax, fig, title, subtitle, path)


def charts(summary, out_dir):
    os.makedirs(out_dir, exist_ok=True)
    pp = summary["per_project"]
    t = summary["totals"]
    keys = [k for k, *_ in PROJECTS]
    stacked([f"{pp[k]['name']}  ({pp[k]['files']} arch.)" for k in keys],
            [pp[k]["by_severity"] for k in keys],
            "Hallazgos por proyecto y severidad",
            f"{t['findings']} hallazgos en {t['files_scanned']} archivos PHP",
            os.path.join(out_dir, "01_proyecto_severidad.png"))
    sev = t["by_severity"]
    fig, ax = plt.subplots(figsize=(10, 3.4))
    y = [2, 1, 0]
    ax.barh(y, [sev[s] for s in SEV_ORDER], height=0.62, color=[C[s] for s in SEV_ORDER],
            edgecolor=C["surface"], linewidth=1.5)
    ax.set_yticks(y, [f"{s} ({'ERROR' if s == 'Alta' else 'WARNING' if s == 'Media' else 'INFO'})"
                      for s in SEV_ORDER])
    vmax = max(sev.values())
    for yi, s in zip(y, SEV_ORDER):
        ax.text(sev[s] + vmax * 0.01, yi, f"{sev[s]}  ({sev[s] / t['findings']:.0%})", va="center",
                fontsize=10, color=C["ink"])
    ax.set_xlim(0, vmax * 1.2)
    _finish(ax, fig, "Distribución por severidad",
            f"Índice de riesgo = Alta×5 + Media×3 + Baja×1 = {t['risk_index']} puntos",
            os.path.join(out_dir, "02_severidad.png"))
    ow = summary["by_owasp"]
    hbar(list(ow.keys()), list(ow.values()), "Hallazgos por categoría OWASP Top 10 (2021)",
         "Las 3 carpetas combinadas", os.path.join(out_dir, "03_owasp.png"), total=t["findings"])
    cl = summary["by_class"]
    hbar(list(cl.keys()), list(cl.values()), "Hallazgos por tipo de vulnerabilidad",
         "Una barra por clase (regla) del ruleset", os.path.join(out_dir, "04_tipo_vulnerabilidad.png"),
         total=t["findings"])
    tf = summary["top_files_core"]
    stacked([f["file"].replace("app/", "") for f in tf], [f["by_severity"] for f in tf],
            "Top 10 archivos con más hallazgos (Core)",
            "Candidatos a revisión y corrección inmediata",
            os.path.join(out_dir, "05_top10_archivos.png"))

    tri = summary.get("triage")
    if tri:
        rows = [r for r in tri["by_rule"] if r["v1"] != r["v2"]]
        labels = [r["vuln_class"] for r in rows][::-1]
        v1 = [r["v1"] for r in rows][::-1]
        v2 = [r["v2"] for r in rows][::-1]
        fig, ax = plt.subplots(figsize=(10, 0.85 * len(rows) + 2.0))
        y = list(range(len(rows)))
        h = 0.36
        ax.barh([i + h / 2 + 0.02 for i in y], v1, height=h, color="#2a78d6", label="v1 (original)")
        ax.barh([i - h / 2 - 0.02 for i in y], v2, height=h, color="#eb6834", label="v2 (tras triaje)")
        vmax = max(v1)
        for i, a, b in zip(y, v1, v2):
            ax.text(a + vmax * 0.01, i + h / 2 + 0.02, str(a), va="center", fontsize=9.5, color=C["ink"])
            ax.text(b + vmax * 0.01, i - h / 2 - 0.02, f"{b}  (−{a - b})", va="center", fontsize=9.5,
                    color=C["ink"])
        ax.set_yticks(y, labels)
        ax.set_xlim(0, vmax * 1.2)
        ax.legend(frameon=False, loc="lower right", fontsize=9.5)
        _finish(ax, fig, "Efecto del triaje: reglas ajustadas (v1 → v2)",
                f"{tri['v1_total']} → {tri['v2_total']} hallazgos ({tri['removed_total']} descartados "
                f"como falsos positivos o reclasificados)",
                os.path.join(out_dir, "06_triaje_v1_v2.png"))


def main():
    ap = argparse.ArgumentParser()
    ap.add_argument("--in", dest="in_dir", default=os.path.join(ROOT, "semgrep", "out"))
    ap.add_argument("--charts", default=os.path.join(ROOT, "charts"))
    ap.add_argument("--prefix", default=os.path.join(ROOT, "semgrep"))
    args = ap.parse_args()

    findings, meta = load(args.in_dir)
    summary = summarize(findings, meta)

    # --- T6: comparación con el ruleset ajustado (v2) ---------------------
    v2_keys, v2_counts = load_v2(args.in_dir)
    if v2_keys is not None:
        v1_counts = collections.Counter(f["rule"] for f in findings)
        cls = {f["rule"]: f["vuln_class"] for f in findings}
        removed = []
        for f in findings:
            kept = fkey(f) in v2_keys
            f["triage_v2"] = "se mantiene" if kept else "descartado"
            if not kept:
                removed.append({k: f[k] for k in ("id", "project", "rule", "vuln_class", "severity",
                                                  "file", "line", "snippet")})
        summary["triage"] = {
            "v1_total": len(findings),
            "v2_total": sum(v2_counts.values()),
            "removed_total": len(removed),
            "by_rule": [{"rule": r, "vuln_class": cls.get(r, r), "v1": v1_counts[r], "v2": v2_counts.get(r, 0)}
                        for r, _ in v1_counts.most_common()],
            "removed": removed,
        }

    # --- Punto extra: reglas taint nuevas ---------------------------------
    extra = load_extra(os.path.join(args.in_dir, "extra.json"))
    summary["extra"] = {
        "total": len(extra),
        "by_rule": dict(collections.Counter(f["vuln_class"] for f in extra).most_common()),
        "files": sorted(set(f["file"] for f in extra)),
        "findings": extra,
    }
    with open(os.path.join(args.prefix, "summary.json"), "w", encoding="utf-8") as fh:
        json.dump(summary, fh, ensure_ascii=False, indent=2)
    with open(os.path.join(args.prefix, "findings.json"), "w", encoding="utf-8") as fh:
        json.dump(findings, fh, ensure_ascii=False, indent=1)
    cols = ["id", "project", "severity", "vuln_class", "owasp", "cwe", "rule", "mode",
            "file", "line", "snippet", "remediation"]
    with open(os.path.join(args.prefix, "findings.csv"), "w", encoding="utf-8-sig", newline="") as fh:
        w = csv.DictWriter(fh, fieldnames=cols, extrasaction="ignore")
        w.writeheader()
        w.writerows(findings)
    charts(summary, args.charts)

    t = summary["totals"]
    print(f"Total: {t['findings']} hallazgos en {t['files_scanned']} archivos | "
          f"Alta {t['by_severity']['Alta']} · Media {t['by_severity']['Media']} · "
          f"Baja {t['by_severity']['Baja']} | Índice de riesgo {t['risk_index']}")
    for key, p in summary["per_project"].items():
        print(f"  {p['name']:<15} {p['files']:>4} archivos  {p['findings']:>4} hallazgos  "
              f"Alta {p['by_severity']['Alta']:>3}  riesgo {p['risk_index']:>4}  postura {p['posture']}")
    print("OWASP:", summary["by_owasp"])
    print("Tipos:", summary["by_class"])
    if "triage" in summary:
        tri = summary["triage"]
        print(f"Triaje v1 -> v2: {tri['v1_total']} -> {tri['v2_total']} ({tri['removed_total']} descartados)")
        for r in tri["by_rule"]:
            if r["v1"] != r["v2"]:
                print(f"   {r['rule']:<28} {r['v1']:>3} -> {r['v2']:>3}")
    print(f"Extra: {summary['extra']['total']} hallazgos nuevos {summary['extra']['by_rule']}")


if __name__ == "__main__":
    main()
