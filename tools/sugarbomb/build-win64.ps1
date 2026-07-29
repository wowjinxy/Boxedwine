param(
    [ValidateSet('Debug', 'Release', 'Test')]
    [string]$Configuration = 'Release',

    [switch]$RunFocusedTests
)

$ErrorActionPreference = 'Stop'

$repositoryRoot = (Resolve-Path -LiteralPath (Join-Path $PSScriptRoot '..\..')).Path
$solution = Join-Path $repositoryRoot 'project\msvc\BoxedWine\BoxedWine.sln'
$vswhere = 'C:\Program Files (x86)\Microsoft Visual Studio\Installer\vswhere.exe'

if (-not (Test-Path -LiteralPath $vswhere)) {
    throw 'Visual Studio Installer vswhere.exe was not found.'
}

$msbuild = & $vswhere -latest -requires Microsoft.Component.MSBuild -find 'MSBuild\**\Bin\MSBuild.exe' |
    Select-Object -First 1
if (-not $msbuild) {
    throw 'MSBuild was not found. Install Visual Studio 2022 with Desktop development with C++.'
}

& $msbuild $solution /m /t:BoxedWine "/p:Configuration=$Configuration" /p:Platform=x64 /p:PlatformToolset=v143 /v:minimal
if ($LASTEXITCODE -ne 0) {
    throw "BoxedWine $Configuration x64 build failed with exit code $LASTEXITCODE."
}

$executable = Join-Path $repositoryRoot "project\msvc\BoxedWine\x64\$Configuration\BoxedWine.exe"
Write-Host "Built $executable"

if ($RunFocusedTests) {
    if ($Configuration -ne 'Test') {
        throw '-RunFocusedTests requires -Configuration Test.'
    }
    & $executable 0 3 1
    if ($LASTEXITCODE -ne 0) {
        throw "Focused Sugarbomb tests failed with exit code $LASTEXITCODE."
    }
}
