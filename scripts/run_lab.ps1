<#
  run_lab.ps1 - Reproduce de punta a punta el laboratorio SAST (Semgrep + bWAPP) en Windows.

  Uso (desde cualquier carpeta):
      powershell -ExecutionPolicy Bypass -File "scripts\run_lab.ps1"            # todo
      powershell -ExecutionPolicy Bypass -File "scripts\run_lab.ps1" -SkipDocker  # sin re-escanear en Docker

  Pasos:
      0. Prerrequisitos (Python 3.12 + venv con semgrep y matplotlib; clon de bWAPP)
      T1 Evidencia del entorno Windows            -> evidencias\T1_entorno_windows.log
      T3 Escaneo oficial en Docker (198 archivos) -> semgrep\out\*.json|sarif|txt, evidencias\T*.log
         Control cruzado nativo en Windows        -> semgrep\out\windows\*.json, evidencias\T3_control_cruzado_windows.log
      T4 Agregacion y graficas                    -> semgrep\summary.json, findings.*, charts\*.png
      T8 Reporte HTML + PDF                       -> reporte\index.html, reporte\Informe_SAST_bWAPP.pdf
#>
param([switch]$SkipDocker)

$ErrorActionPreference = 'Continue'
$Root = Split-Path -Parent $PSScriptRoot
Set-Location $Root
$env:PYTHONUTF8 = '1'
[Console]::OutputEncoding = [Text.Encoding]::UTF8
$py = '.venv\Scripts\python.exe'
$sg = '.venv\Scripts\semgrep.exe'
$R  = 'semgrep\php-sast-rules.yml'
$off = '--metrics=off --disable-version-check --no-git-ignore'

function Step($t) { Write-Host "`n=== $t" -ForegroundColor Cyan }
function Native($cmd) { "`n> $cmd"; cmd /c "$cmd 2>&1" }
function Save($lines, $path) { $lines | Out-File -FilePath $path -Encoding utf8; $lines }

# --------------------------------------------------------------------------
Step '0. Prerrequisitos'
if (-not (Test-Path $py)) {
    $base = "$env:LOCALAPPDATA\Programs\Python\Python312\python.exe"
    if (-not (Test-Path $base)) {
        winget install --id Python.Python.3.12 -e --scope user --silent --accept-package-agreements --accept-source-agreements
    }
    & $base -m venv .venv
    & $py -m pip install --upgrade pip
    & $py -m pip install semgrep matplotlib
}
if (-not (Test-Path 'bWAPP\.git')) { git clone --depth 1 https://github.com/raesene/bWAPP.git }
New-Item -ItemType Directory -Force 'evidencias', 'semgrep\out\windows' | Out-Null

# --------------------------------------------------------------------------
Step 'T1. Evidencia del entorno (Windows)'
$t1 = & {
    '=== T1 - Entorno Windows - ' + (Get-Date -Format 'yyyy-MM-dd HH:mm:ss')
    $os = Get-CimInstance Win32_OperatingSystem
    "SO: $($os.Caption) (build $($os.BuildNumber))"
    Native "$py --version"
    Native "$sg --version"
    Native 'git --version'
    Native 'docker --version'
    Native 'git -C bWAPP log -1 --format="%H %cd"'
    "`n> ls bWAPP/app   (primeras 20 entradas)"
    Get-ChildItem bWAPP\app -Name | Select-Object -First 20
    $php = Get-ChildItem -Recurse bWAPP\app -Filter *.php
    $core  = @($php | Where-Object { $_.FullName -notmatch '\\app\\(admin|soap)\\' }).Count
    $admin = @($php | Where-Object { $_.FullName -match '\\app\\admin\\' }).Count
    $soap  = @($php | Where-Object { $_.FullName -match '\\app\\soap\\' }).Count
    "`n> archivos PHP en bWAPP/app: $($php.Count)   (Core $core / admin $admin / soap $soap)"
    $inGit = @(git -C bWAPP ls-files app | Where-Object { $_ -like '*.php' })
    "> archivos PHP segun git (git ls-files app): $($inGit.Count)"
    $missing = @($inGit | Where-Object { -not (Test-Path (Join-Path 'bWAPP' $_)) })
    $blocked = @(foreach ($f in $php) {
        try { [IO.File]::ReadAllBytes($f.FullName) | Out-Null } catch { $f.FullName.Substring($Root.Length + 1) }
    })
    "> archivos PHP eliminados o bloqueados por el antivirus en Windows: $($missing.Count + $blocked.Count)"
    $missing | ForEach-Object { "     $_   (eliminado del disco por Windows Defender)" }
    $blocked | ForEach-Object { "     $_   (presente pero ilegible)" }
    '> por eso el escaneo oficial se ejecuta dentro de Docker (ver T1_entorno_docker.log)'
}
Save $t1 'evidencias\T1_entorno_windows.log' | Out-Host

# --------------------------------------------------------------------------
if (-not $SkipDocker) {
    Step 'T2/T3/T6/EXTRA. Escaneo oficial dentro de Docker (semgrep/semgrep:1.185.0)'
    docker run --rm -v "${Root}:/src" semgrep/semgrep:1.185.0 sh /src/scripts/run_scans_docker.sh
}

# --------------------------------------------------------------------------
Step 'T3. Control cruzado: mismo escaneo nativo en Windows'
$keep = 'Findings:|Rules run:|Targets scanned:|^Ran '
$t3w = & {
    '=== Control cruzado nativo (Windows, semgrep ' + ((cmd /c "$sg --version") -join '') + ')'
    "`n> semgrep scan --config $R $off --exclude admin --exclude soap --json -o semgrep\out\windows\core.json bWAPP\app"
    cmd /c "$sg scan --config $R $off --exclude admin --exclude soap --json -o semgrep\out\windows\core.json bWAPP\app 2>&1" | Select-String $keep | ForEach-Object { $_.Line.Trim() }
    "`n> semgrep scan --config $R $off --json -o semgrep\out\windows\admin.json bWAPP\app\admin"
    cmd /c "$sg scan --config $R $off --json -o semgrep\out\windows\admin.json bWAPP\app\admin 2>&1" | Select-String $keep | ForEach-Object { $_.Line.Trim() }
    "`n> semgrep scan --config $R $off --json -o semgrep\out\windows\soap.json bWAPP\app\soap"
    cmd /c "$sg scan --config $R $off --json -o semgrep\out\windows\soap.json bWAPP\app\soap 2>&1" | Select-String $keep | ForEach-Object { $_.Line.Trim() }
    "`n> Diferencias Docker vs Windows (archivo, linea, regla):"
    & $py -I -c @"
import json
for p in ('core', 'admin', 'soap'):
    k = lambda r: (r['path'].replace(chr(92), '/').split('bWAPP/', 1)[-1], r['start']['line'], r['check_id'].split('.')[-1])
    dr = json.load(open(f'semgrep/out/{p}.json', encoding='utf-8'))['results']
    wr = json.load(open(f'semgrep/out/windows/{p}.json', encoding='utf-8'))['results']
    d, w = set(map(k, dr)), set(map(k, wr))
    print(f'   {p:<6} docker={len(dr):>3}  windows={len(wr):>3}  solo_docker={sorted(d - w)}  solo_windows={sorted(w - d)}')
"@
}
Save $t3w 'evidencias\T3_control_cruzado_windows.log' | Out-Host

# --------------------------------------------------------------------------
Step 'T4. Agregacion, postura y graficas'
& $py -I semgrep\analyze.py

# --------------------------------------------------------------------------
Step 'T8. Reporte HTML y PDF'
& $py -I reporte\build_report.py
$edge = @("${env:ProgramFiles(x86)}\Microsoft\Edge\Application\msedge.exe",
          "$env:ProgramFiles\Microsoft\Edge\Application\msedge.exe") | Where-Object { Test-Path $_ } | Select-Object -First 1
if ($edge) {
    Step 'T8. Despliegue en localhost, PDF y capturas de evidencia'
    $srv = Start-Process -FilePath $py -ArgumentList '-m', 'http.server', '8081', '-d', 'reporte', '--bind', '127.0.0.1' -PassThru -WindowStyle Hidden
    Start-Sleep -Seconds 2
    $prof = Join-Path $env:TEMP 'edge-shot-profile'   # perfil aparte: funciona aunque Edge ya este abierto
    $pdf = Join-Path $Root 'reporte\Informe_SAST_bWAPP.pdf'
    Remove-Item $pdf -ErrorAction SilentlyContinue
    & $edge --headless=new --disable-gpu --no-pdf-header-footer "--user-data-dir=$prof" --virtual-time-budget=10000 "--print-to-pdf=$pdf" 'http://localhost:8081/?print' 2>$null | Out-Null
    Start-Sleep -Seconds 2
    if (Test-Path $pdf) { "PDF generado: reporte\Informe_SAST_bWAPP.pdf ($([math]::Round((Get-Item $pdf).Length / 1KB)) KB)" } else { 'No se pudo generar el PDF con Edge.' }
    $cap = Join-Path $Root 'evidencias\capturas'
    New-Item -ItemType Directory -Force $cap | Out-Null
    $shots = @(@('01_resumen', '', 1100), @('02_graficas', 'graficas', 1500), @('03_hallazgos', 'hallazgos', 3400),
               @('05_triaje', 'triaje', 2300), @('06_postura', 'postura', 1250), @('07_reglas', 'reglas', 2600),
               @('08_evidencia', 'evidencia', 2600))
    foreach ($s in $shots) {
        $png = Join-Path $cap "$($s[0]).png"
        $u = if ($s[1]) { "http://localhost:8081/?only=$($s[1])" } else { 'http://localhost:8081/' }
        & $edge --headless=new --disable-gpu --hide-scrollbars "--user-data-dir=$prof" "--window-size=1280,$($s[2])" --virtual-time-budget=6000 "--screenshot=$png" $u 2>$null | Out-Null
        Start-Sleep -Milliseconds 400
        if (Test-Path $png) { "captura: evidencias\capturas\$($s[0]).png" }
    }
    Stop-Process -Id $srv.Id -Force -ErrorAction SilentlyContinue
}
Step 'Listo'
'Abra reporte\index.html en el navegador o sirvalo con:  .venv\Scripts\python.exe -m http.server 8080 -d reporte'
