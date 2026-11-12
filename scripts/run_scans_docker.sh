#!/bin/sh
# =============================================================================
# run_scans_docker.sh — Escaneo SAST oficial del laboratorio (dentro de Docker)
#
# Se ejecuta en la imagen oficial semgrep/semgrep:1.185.0 con la carpeta del
# laboratorio montada en /src. bWAPP se clona DENTRO del contenedor, por lo
# que los 198 archivos PHP se analizan completos (en Windows, el antivirus
# pone en cuarentena app/php_eval.php por contener eval($_REQUEST[...])).
#
# Uso (PowerShell, desde la raíz del laboratorio):
#   docker run --rm -v "${PWD}:/src" semgrep/semgrep:1.185.0 sh /src/scripts/run_scans_docker.sh
# =============================================================================
set -e
SRC=/src
OUT=$SRC/semgrep/out
EV=$SRC/evidencias
R=$SRC/semgrep/php-sast-rules.yml
R2=$SRC/semgrep/php-sast-rules-v2.yml
RX=$SRC/semgrep/extra/php-extra-rules.yml
OFF="--metrics=off --disable-version-check --no-git-ignore"
mkdir -p "$OUT" "$OUT/v2" "$EV"

step() { echo; echo "\$ $*"; }

{
  echo "=== T1 — Entorno (contenedor semgrep/semgrep:1.185.0) — $(date -u '+%Y-%m-%d %H:%M:%S UTC')"
  step semgrep --version;            semgrep --version
  step git --version;                git --version
  cd /tmp && rm -rf bWAPP
  step git clone --depth 1 https://github.com/raesene/bWAPP.git
  git clone --depth 1 https://github.com/raesene/bWAPP.git 2>&1
  step git -C bWAPP log -1 --format='%H %cd'
  git -C bWAPP log -1 --format='%H %cd'
  step "ls bWAPP/app | head -20"
  ls bWAPP/app | head -20
  step "find bWAPP/app -name '*.php' | wc -l"
  find bWAPP/app -name '*.php' | wc -l
  step "find bWAPP/app -name '*.php' -not -path '*/admin/*' -not -path '*/soap/*' | wc -l   # Core"
  find bWAPP/app -name '*.php' -not -path '*/admin/*' -not -path '*/soap/*' | wc -l
  step "ls bWAPP/app/admin bWAPP/app/soap"
  ls bWAPP/app/admin bWAPP/app/soap
} 2>&1 | tee "$EV/T1_entorno_docker.log"

cd /tmp
{
  echo "=== T2 — Validación y pruebas unitarias de las reglas"
  step semgrep --validate --config php-sast-rules.yml
  semgrep --validate --config "$R" --metrics=off 2>&1 | tail -n 2
  step semgrep --test --config php-sast-rules.yml tests/php-sast-rules.php
  semgrep --test --config "$R" "$SRC/semgrep/tests/php-sast-rules.php" --metrics=off 2>&1 || true
  step semgrep --test --config php-sast-rules-v2.yml tests/php-sast-rules-v2.php
  semgrep --test --config "$R2" "$SRC/semgrep/tests/php-sast-rules-v2.php" --metrics=off 2>&1 || true
  step semgrep --test --config extra/php-extra-rules.yml extra/php-extra-rules.php
  semgrep --test --config "$RX" "$SRC/semgrep/extra/php-extra-rules.php" --metrics=off 2>&1 || true
} 2>&1 | tee "$EV/T2_pruebas_reglas.log"

{
  echo "=== T3 — Escaneo de las 3 carpetas con php-sast-rules.yml (14 reglas)"
  step "semgrep scan --config php-sast-rules.yml $OFF --exclude admin --exclude soap bWAPP/app   # Proyecto 1 — Core"
  semgrep scan --config "$R" $OFF --exclude admin --exclude soap \
      --json-output="$OUT/core.json" --sarif-output="$OUT/core.sarif" --text-output="$OUT/core.txt" \
      bWAPP/app 2>&1 | grep -v '^ *$' | sed -n '/Scan Summary/,$p'
  step "semgrep scan --config php-sast-rules.yml $OFF bWAPP/app/admin   # Proyecto 2 — admin"
  semgrep scan --config "$R" $OFF \
      --json-output="$OUT/admin.json" --sarif-output="$OUT/admin.sarif" --text-output="$OUT/admin.txt" \
      bWAPP/app/admin 2>&1 | grep -v '^ *$' | sed -n '/Scan Summary/,$p'
  step "semgrep scan --config php-sast-rules.yml $OFF bWAPP/app/soap   # Proyecto 3 — soap (NuSOAP)"
  semgrep scan --config "$R" $OFF \
      --json-output="$OUT/soap.json" --sarif-output="$OUT/soap.sarif" --text-output="$OUT/soap.txt" \
      bWAPP/app/soap 2>&1 | grep -v '^ *$' | sed -n '/Scan Summary/,$p'
  step "semgrep scan --config php-sast-rules.yml --severity ERROR --exclude admin --exclude soap bWAPP/app   # solo Alta (Core)"
  semgrep scan --config "$R" $OFF --severity ERROR --exclude admin --exclude soap \
      --json-output="$OUT/core_error_only.json" bWAPP/app 2>&1 | grep -v '^ *$' | sed -n '/Scan Summary/,$p'
  step "semgrep scan --config php-sast-rules.yml --sarif -o bwapp-all.sarif bWAPP/app   # SARIF combinado (CI/GitHub)"
  semgrep scan --config "$R" $OFF --sarif -o "$OUT/bwapp-all.sarif" bWAPP/app 2>&1 | grep -v '^ *$' | sed -n '/Scan Summary/,$p'
} 2>&1 | tee "$EV/T3_escaneo.log"

{
  echo "=== T6 — Re-escaneo con el ruleset ajustado tras el triaje (php-sast-rules-v2.yml)"
  step "semgrep scan --config php-sast-rules-v2.yml ... (core / admin / soap)"
  semgrep scan --config "$R2" $OFF --exclude admin --exclude soap --json -o "$OUT/v2/core.json" bWAPP/app 2>&1 | grep -v '^ *$' | sed -n '/Scan Summary/,$p'
  semgrep scan --config "$R2" $OFF --json -o "$OUT/v2/admin.json" bWAPP/app/admin 2>&1 | grep -v '^ *$' | sed -n '/Scan Summary/,$p'
  semgrep scan --config "$R2" $OFF --json -o "$OUT/v2/soap.json" bWAPP/app/soap 2>&1 | grep -v '^ *$' | sed -n '/Scan Summary/,$p'
} 2>&1 | tee "$EV/T6_reescaneo_v2.log"

{
  echo "=== EXTRA — Reglas taint nuevas (path traversal y subida de archivos)"
  step "semgrep scan --config extra/php-extra-rules.yml bWAPP/app"
  semgrep scan --config "$RX" $OFF --json-output="$OUT/extra.json" --sarif-output="$OUT/extra.sarif" \
      --text-output="$OUT/extra.txt" bWAPP/app 2>&1 | grep -v '^ *$' | sed -n '/Scan Summary/,$p'
} 2>&1 | tee "$EV/EXTRA_reglas_nuevas.log"

echo; echo "Listo. Resultados en semgrep/out/ y evidencias en evidencias/"
