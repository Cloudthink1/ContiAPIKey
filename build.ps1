#Requires -Version 7.0
param([switch] $Offline, [switch] $Test, [switch] $Native)
$ErrorActionPreference = 'Stop'
$root = $PSScriptRoot
$cache = Join-Path $root '.build-cache'
$tool = Get-Command cargo -CommandType Application -ErrorAction SilentlyContinue | Select-Object -First 1
$fallback = Join-Path (Split-Path -Parent $root) 'codex-apdu/.apdu-build/rustup/toolchains/1.93.0-x86_64-pc-windows-msvc/bin'
$cargo = if ($tool) { $tool.Source } else { Join-Path $fallback 'cargo.exe' }
if (!(Test-Path -LiteralPath $cargo -PathType Leaf)) { throw 'Install the Rust toolchain listed in rust-toolchain.toml.' }
$oldPath = $env:Path
$oldCargo = $env:CARGO_HOME
Push-Location $root
try {
    $env:Path = "$(Split-Path -Parent $cargo);$oldPath"
    if (Test-Path -LiteralPath (Join-Path $cache 'cargo/registry')) { $env:CARGO_HOME = Join-Path $cache 'cargo' }
    $network = @()
    if ($Offline) { $network += '--offline' }
    & $cargo build --locked --bins @network
    if ($LASTEXITCODE -ne 0) { throw 'Gateway build failed.' }
    if ($Native) { & (Join-Path $root 'native/build.ps1') -Offline:$Offline }
    if ($Test) {
        & $cargo test --locked @network
        if ($LASTEXITCODE -ne 0) { throw 'Gateway tests failed.' }
        if ($Native) {
            & $cargo test --locked --lib @network native_tls -- --ignored --test-threads=1
            if ($LASTEXITCODE -ne 0) { throw 'Native chip TLS tests failed.' }
        }
    }
} finally {
    Pop-Location
    $env:Path = $oldPath
    [Environment]::SetEnvironmentVariable('CARGO_HOME', ($oldCargo ?? [NullString]::Value), 'Process')
}
