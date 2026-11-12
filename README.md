# Práctica SAST con Semgrep: análisis del código de bWAPP

**Autor:** Walter Sánchez · Maestría en Seguridad Informática (MASI 2026) · Seguridad en Aplicaciones
Universidad Mariano Gálvez de Guatemala

Evaluación SAST de los 3 proyectos (carpetas) del repositorio [raesene/bWAPP](https://github.com/raesene/bWAPP)
con un ruleset local de Semgrep de 14 reglas mapeadas a OWASP Top 10 (2021) y CWE, más 2 reglas taint nuevas.

> bWAPP es una aplicación **deliberadamente vulnerable** y de código abierto, creada para entrenamiento.
> El análisis es estático (el código no se ejecuta) y se hace sobre una copia local.

## Resultados

| Proyecto | Carpeta | Archivos PHP | Hallazgos | Alta | Media | Baja | Índice | Postura |
|---|---|---:|---:|---:|---:|---:|---:|---|
| Core bWAPP | `app/` (sin admin ni soap) | 183 | **207** | 58 | 146 | 3 | 731 | 🔴 Crítica |
| admin | `app/admin/` | 3 | **2** | 0 | 1 | 1 | 4 | 🟡 Media |
| soap (NuSOAP) | `app/soap/` | 12 | **21** | 1 | 20 | 0 | 65 | 🟠 Alta |
| **Total** | | **198** | **230** | 59 | 167 | 4 | **800** | **Crítica** |

* Índice de riesgo = Alta×5 + Media×3 + Baja×1 = **800** puntos (4,04 por archivo).
* OWASP: A03 Injection 154 (67 %), A02 Cryptographic Failures 46, A01 Broken Access Control 19, A07 6, A05 4, A08 1.
* Triaje (T6): 5 reglas ajustadas en `php-sast-rules-v2.yml` → **230 → 171** hallazgos (59 falsos positivos o reclasificados).
* Extra: 2 reglas taint nuevas (path traversal, subida sin restricción) → **15** hallazgos que el ruleset base no cubre.

**Dashboard publicado:** https://wsanchezf.github.io/SAST_Semgrep_bWAPP/ · **PDF:** [`reporte/Informe_SAST_bWAPP.pdf`](reporte/Informe_SAST_bWAPP.pdf)
· **Alertas SARIF:** pestaña [Security › Code scanning](https://github.com/WsanchezF/SAST_Semgrep_bWAPP/security/code-scanning)

## CI/CD (GitHub Actions)

`.github/workflows/semgrep.yml` se ejecuta en cada push a `main`, en cada pull request y a mano (*Run workflow*):

| Job | Qué hace | Resultado esperado |
|---|---|---|
| **SAST con Semgrep (SARIF)** | Pruebas de las reglas (14/14, 14/14, 2/2) y escaneo de `bWAPP/app` con las 14 reglas + 2 extra; sube el SARIF a Code Scanning | ✅ |
| **Quality gate (0 hallazgos Alta)** | `semgrep --severity ERROR --error` | ❌ **a propósito**: bWAPP tiene 59 hallazgos Alta, y esto es lo que bloquearía un despliegue real |
| **Publicar dashboard en GitHub Pages** | Publica `reporte/index.html`, el PDF y las gráficas | ✅ |

bWAPP se incluye como **submódulo** fijado al commit `53bcfdd` de [raesene/bWAPP](https://github.com/raesene/bWAPP):
el código vulnerable no se redistribuye desde este repositorio. Para clonarlo con todo: `git clone --recurse-submodules <url>`.

## Dónde está cada entregable

| Tarea | Entregable |
|---|---|
| T1 Entorno | `evidencias/T1_entorno_windows.log`, `evidencias/T1_entorno_docker.log` (`semgrep --version`, `ls bWAPP/app`) |
| T2 Reglas | `semgrep/php-sast-rules.yml` (14 reglas), pruebas `semgrep/tests/php-sast-rules.php` (14/14), reporte § Reglas |
| T3 Escaneo | `semgrep/out/{core,admin,soap}.json` (+ `.sarif`, `.txt`), `evidencias/T3_escaneo.log` |
| T4 Gráficas | `charts/01..06_*.png` generadas por `semgrep/analyze.py` desde el JSON |
| T5 Hallazgos | reporte § Hallazgos (8 documentados), `semgrep/findings.csv` (los 230) |
| T6 Triaje | `semgrep/php-sast-rules-v2.yml`, `semgrep/tests/php-sast-rules-v2.php`, `semgrep/out/v2/`, reporte § Triaje |
| T7 Postura | `semgrep/summary.json` (semáforo calculado), reporte § Postura |
| T8 Despliegue | `reporte/index.html` (dashboard), `reporte/Informe_SAST_bWAPP.pdf`, `evidencias/capturas/*.png` (desplegado en localhost) |
| Extra (+5) | `semgrep/extra/php-extra-rules.yml` (2 reglas taint nuevas, 15 hallazgos) y `.github/workflows/semgrep.yml` (SARIF en CI) |

## Reproducir

Requisitos: Windows con PowerShell, Git, Docker Desktop y (opcional) Python 3.12. El script instala lo que falte.

```powershell
powershell -ExecutionPolicy Bypass -File scripts\run_lab.ps1
```

Paso a paso:

```powershell
# 1. Entorno
winget install --id Python.Python.3.12 -e --scope user
& "$env:LOCALAPPDATA\Programs\Python\Python312\python.exe" -m venv .venv
.venv\Scripts\python.exe -m pip install semgrep matplotlib
git clone --depth 1 https://github.com/raesene/bWAPP.git
.venv\Scripts\semgrep.exe --version            # 1.185.0

# 2. Pruebas de las reglas
.venv\Scripts\semgrep.exe --test --config semgrep\php-sast-rules.yml semgrep\tests\php-sast-rules.php

# 3. Escaneo oficial de las 3 carpetas (en Docker: ver nota)
docker run --rm -v "${PWD}:/src" semgrep/semgrep:1.185.0 sh /src/scripts/run_scans_docker.sh

# 4. Gráficas, resumen y reporte
.venv\Scripts\python.exe semgrep\analyze.py
.venv\Scripts\python.exe reporte\build_report.py
.venv\Scripts\python.exe -m http.server 8080 -d reporte     # http://localhost:8080
```

### Nota: Windows Defender y `php_eval.php`

Al clonar bWAPP en Windows, Defender pone en cuarentena `app/php_eval.php` porque contiene
`@eval($_REQUEST["eval"])` (una webshell). **No se desactivó el antivirus.** El escaneo oficial se
ejecuta dentro del contenedor `semgrep/semgrep:1.185.0`, que clona bWAPP en su propio sistema de
archivos y lo lee como texto. El escaneo nativo de control en Windows (`semgrep/out/windows/`)
da exactamente **un hallazgo menos**: `php_eval.php:82`.

## Estructura

```
SAST_Semgrep_bWAPP/
├── semgrep/
│   ├── php-sast-rules.yml        ruleset (14 reglas, OWASP/CWE)
│   ├── php-sast-rules-v2.yml     ruleset ajustado tras el triaje (T6)
│   ├── extra/                    2 reglas taint nuevas + pruebas (puntos extra)
│   ├── tests/                    pruebas unitarias (semgrep --test)
│   ├── analyze.py                agregación, semáforo y gráficas
│   ├── out/                      JSON / SARIF / TXT de los escaneos (v1, v2, extra, windows)
│   ├── summary.json              conteos por proyecto, severidad, OWASP, tipo, archivo, triaje
│   └── findings.json|csv         los 230 hallazgos con fragmento de código
├── charts/                       6 gráficas PNG
├── reporte/                      dashboard HTML, plantilla, generador y PDF
├── evidencias/                   logs de cada tarea y capturas del reporte desplegado
├── scripts/                      run_lab.ps1 (Windows) y run_scans_docker.sh (contenedor)
├── .github/workflows/semgrep.yml integración CI con SARIF
└── bWAPP/                        código analizado (clon de raesene/bWAPP @ 53bcfdd)
```
