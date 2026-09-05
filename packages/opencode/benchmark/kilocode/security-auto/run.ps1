# Run from any directory; also find the task-local Bun used on this Windows checkout.
$ErrorActionPreference = 'Stop'
$repo = [System.IO.Path]::GetFullPath((Join-Path $PSScriptRoot '../../../../..'))
$command = Get-Command bun -ErrorAction SilentlyContinue
$runtime = if ($command) { $command.Source } else { Join-Path $repo '.kilo-dev/security-benchmark/tools/bun-windows-x64/bun.exe' }
if (-not (Test-Path -LiteralPath $runtime)) { throw 'Bun 1.3.14 is required. Install Bun, then run bun install --frozen-lockfile from the repository root.' }
Push-Location $repo
try {
    & $runtime (Join-Path $PSScriptRoot 'bench.ts') @args
    exit $LASTEXITCODE
} finally {
    Pop-Location
}
