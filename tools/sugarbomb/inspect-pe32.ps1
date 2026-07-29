param(
    [Parameter(Mandatory)]
    [string]$Path,

    [switch]$Imports
)

$ErrorActionPreference = 'Stop'

$repositoryRoot = (Resolve-Path -LiteralPath (Join-Path $PSScriptRoot '..\..')).Path
$inspector = Join-Path $repositoryRoot 'project\msvc\BoxedWine\x64\Release\BoxedWine.exe'
$target = (Resolve-Path -LiteralPath $Path).Path

if (-not (Test-Path -LiteralPath $inspector)) {
    throw 'Release inspector is missing. Run build-win64.ps1 -Configuration Release first.'
}

$command = if ($Imports) { '--sugarbomb-pe-imports' } else { '--sugarbomb-pe-info' }
& $inspector $command $target
if ($LASTEXITCODE -ne 0) {
    throw "PE32 inspection failed with exit code $LASTEXITCODE."
}
