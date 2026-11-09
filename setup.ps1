<#
.SYNOPSIS
    PE Parser 개발 환경 원클릭 설치 스크립트 (Windows x64)

.DESCRIPTION
    없는 것만 설치하고, 이미 있는 것은 건너뛴다. 여러 번 실행해도 안전하다.
      1. Visual Studio C++ 빌드 도구 (MSVC)  - 없으면 VS 2022 Build Tools 설치 (winget)
      2. CMake                               - VS 내장 CMake 우선, 없으면 winget 설치
      3. Python 3                            - 없으면 winget 설치
      4. aqtinstall -> Qt 6.8.3 (msvc2022_64) - Qt 계정 불필요
      5. (-Build 지정 시) configure + build

.EXAMPLE
    .\setup.cmd                 # 환경만 설치
    .\setup.cmd -Build          # 설치 후 Debug 빌드까지
    .\setup.cmd -QtRoot D:\Qt   # Qt를 다른 위치에 설치 (사용자 환경변수 QT_ROOT 자동 등록)
#>
[CmdletBinding()]
param(
    [string]$QtRoot = $(if ($env:QT_ROOT) { $env:QT_ROOT } else { 'C:\Qt' }),
    [string]$QtVersion = '6.8.3',
    [string]$QtArch = 'win64_msvc2022_64',
    [switch]$Build,
    [ValidateSet('debug', 'release')]
    [string]$Config = 'debug'
)

$ErrorActionPreference = 'Stop'
$AqtVersion = '3.3.0'
$QtArchDir = $QtArch -replace '^win64_', ''   # win64_msvc2022_64 -> msvc2022_64

function Write-Step($msg) { Write-Host "`n==> $msg" -ForegroundColor Cyan }
function Write-Ok($msg) { Write-Host "    [OK] $msg" -ForegroundColor Green }
function Write-Info($msg) { Write-Host "    $msg" }

function Update-SessionPath {
    $machine = [Environment]::GetEnvironmentVariable('Path', 'Machine')
    $user = [Environment]::GetEnvironmentVariable('Path', 'User')
    $env:Path = "$machine;$user"
}

function Assert-ExitCode($what) {
    if ($LASTEXITCODE -ne 0) { throw "$what 실패 (exit code $LASTEXITCODE)" }
}

function Assert-Winget {
    if (-not (Get-Command winget -ErrorAction SilentlyContinue)) {
        throw "winget이 없습니다. Microsoft Store에서 '앱 설치 관리자(App Installer)'를 설치한 뒤 다시 실행하세요."
    }
}

function Install-WithWinget([string]$id, [string[]]$extra = @()) {
    Assert-Winget
    Write-Info "winget install $id ..."
    & winget install --id $id -e --accept-package-agreements --accept-source-agreements @extra
    Assert-ExitCode "winget install $id"
    Update-SessionPath
}

# ---------------------------------------------------------------------------
# 1. Visual Studio C++ 도구
# ---------------------------------------------------------------------------
Write-Step 'Visual Studio C++ 빌드 도구 확인'
$vswhere = Join-Path ${env:ProgramFiles(x86)} 'Microsoft Visual Studio\Installer\vswhere.exe'

function Find-VS {
    if (-not (Test-Path $vswhere)) { return $null }
    $path = & $vswhere -latest -products * -requires Microsoft.VisualStudio.Component.VC.Tools.x86.x64 -property installationPath
    if ($path) { return ($path | Select-Object -First 1) }
    return $null
}

$vsPath = Find-VS
if (-not $vsPath) {
    Write-Info 'MSVC가 없습니다. Visual Studio 2022 Build Tools (C++ 워크로드)를 설치합니다. (수 GB, UAC 창이 뜰 수 있음)'
    Install-WithWinget 'Microsoft.VisualStudio.2022.BuildTools' @(
        '--override', '--wait --passive --add Microsoft.VisualStudio.Workload.VCTools --includeRecommended')
    $vsPath = Find-VS
    if (-not $vsPath) { throw 'Build Tools 설치 후에도 MSVC를 찾지 못했습니다. Visual Studio Installer에서 "C++를 사용한 데스크톱 개발"을 확인하세요.' }
}
Write-Ok "MSVC: $vsPath"

# ---------------------------------------------------------------------------
# 2. CMake (3.21+)
# ---------------------------------------------------------------------------
Write-Step 'CMake 확인'
if (-not (Get-Command cmake -ErrorAction SilentlyContinue)) {
    $vsCmake = Join-Path $vsPath 'Common7\IDE\CommonExtensions\Microsoft\CMake\CMake\bin'
    if (Test-Path (Join-Path $vsCmake 'cmake.exe')) {
        $env:Path = "$vsCmake;$env:Path"
        Write-Info "VS 내장 CMake 사용 (이 세션에만 PATH 추가): $vsCmake"
    } else {
        Install-WithWinget 'Kitware.CMake'
    }
}
Write-Ok ((& cmake --version | Select-Object -First 1))

# ---------------------------------------------------------------------------
# 3. Python 3
# ---------------------------------------------------------------------------
Write-Step 'Python 확인'
function Find-Python {
    # WindowsApps 의 python.exe 는 스토어로 연결되는 가짜이므로 실제 실행해 본다
    foreach ($c in @(@('py', '-3'), @('python'), @('python3'))) {
        if (Get-Command $c[0] -ErrorAction SilentlyContinue) {
            $cmdArgs = @($c | Select-Object -Skip 1) + @('-c', 'import sys; print(sys.version_info[0])')
            $out = & $c[0] @cmdArgs 2>$null
            if ($LASTEXITCODE -eq 0 -and "$out".Trim() -eq '3') { return , $c }
        }
    }
    return $null
}

$py = Find-Python
if (-not $py) {
    Install-WithWinget 'Python.Python.3.13'
    $py = Find-Python
    if (-not $py) { throw 'Python 설치 후에도 찾지 못했습니다. 새 터미널에서 다시 실행해 보세요.' }
}
$pyExe = $py[0]
$pyArgs = @($py | Select-Object -Skip 1)
function Invoke-Py { & $pyExe @pyArgs @args }
Write-Ok ((Invoke-Py --version) -join ' ')

# ---------------------------------------------------------------------------
# 4. Qt (aqtinstall)
# ---------------------------------------------------------------------------
Write-Step "Qt $QtVersion ($QtArchDir) 확인"
$qtPrefix = Join-Path $QtRoot "$QtVersion\$QtArchDir"
$qtConfig = Join-Path $qtPrefix 'lib\cmake\Qt6\Qt6Config.cmake'

if (Test-Path $qtConfig) {
    Write-Ok "이미 설치됨: $qtPrefix"
} else {
    Write-Info "aqtinstall $AqtVersion 설치"
    Invoke-Py -m pip install --user --disable-pip-version-check -q "aqtinstall==$AqtVersion"
    Assert-ExitCode 'pip install aqtinstall'

    Write-Info "Qt 다운로드/설치 -> $QtRoot (네트워크에 따라 수 분~십수 분)"
    Invoke-Py -m aqt install-qt windows desktop $QtVersion $QtArch -O $QtRoot
    Assert-ExitCode 'aqt install-qt'
    if (-not (Test-Path $qtConfig)) { throw "Qt 설치 후에도 $qtConfig 가 없습니다." }
    Write-Ok "설치 완료: $qtPrefix"
}

# 기본 위치(C:\Qt)가 아니면 CMake가 찾을 수 있도록 사용자 환경변수 등록
$normalized = [IO.Path]::GetFullPath($QtRoot).TrimEnd('\')
if ($normalized -ne 'C:\Qt') {
    [Environment]::SetEnvironmentVariable('QT_ROOT', $normalized, 'User')
    $env:QT_ROOT = $normalized
    Write-Ok "사용자 환경변수 QT_ROOT=$normalized 등록 (새 터미널부터 적용)"
}

# ---------------------------------------------------------------------------
# 5. 빌드 (옵션)
# ---------------------------------------------------------------------------
if ($Build) {
    Write-Step "Configure + Build ($Config)"
    Push-Location $PSScriptRoot
    try {
        & cmake --preset msvc
        Assert-ExitCode 'cmake configure'
        & cmake --build --preset $Config
        Assert-ExitCode 'cmake build'
    } finally {
        Pop-Location
    }
    $cfgDir = (Get-Culture).TextInfo.ToTitleCase($Config)
    Write-Ok "실행 파일: $PSScriptRoot\build\$cfgDir\PEParser.exe"
}

Write-Host "`n완료!" -ForegroundColor Green
if (-not $Build) { Write-Host '빌드: cmake --preset msvc; cmake --build --preset debug   (또는 .\setup.cmd -Build)' }
