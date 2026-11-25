#Requires -Version 7.0
param([switch] $Offline)
$ErrorActionPreference = 'Stop'
if (!$IsWindows) { throw 'The native chip adapter requires Windows x64.' }
$root = Split-Path -Parent $PSScriptRoot
$cache = Join-Path $root '.build-cache'
New-Item -ItemType Directory -Force -Path $cache | Out-Null
$archive = Join-Path $cache 'mbedtls-3.6.8.tar.bz2'
$expected = 'BC54B818E87F49C0B3281DD85D24ADAEDE0E63B4E822E3FBD49C005A38B9595B'
if (!(Test-Path -LiteralPath $archive -PathType Leaf)) {
    $existing = Join-Path (Split-Path -Parent $root) 'codex-apdu/.apdu-build/mbedtls-3.6.8.tar.bz2'
    if (Test-Path -LiteralPath $existing -PathType Leaf) {
        Copy-Item -LiteralPath $existing -Destination $archive
    } elseif ($Offline) {
        throw 'The Mbed TLS archive is unavailable offline.'
    } else {
        & curl.exe --fail --location --output "$archive.download" 'https://github.com/Mbed-TLS/mbedtls/releases/download/mbedtls-3.6.8/mbedtls-3.6.8.tar.bz2'
        if ($LASTEXITCODE -ne 0) { throw 'Mbed TLS download failed.' }
        if ((Get-FileHash -LiteralPath "$archive.download").Hash -ne $expected) { throw 'Mbed TLS checksum mismatch.' }
        Move-Item -LiteralPath "$archive.download" -Destination $archive
    }
}
if ((Get-FileHash -LiteralPath $archive).Hash -ne $expected) { throw 'Mbed TLS checksum mismatch.' }
$cmake = if ($env:CMAKE) { $env:CMAKE } else { (Get-Command cmake -ErrorAction SilentlyContinue).Source }
if (!$cmake) {
    $vswhere = Join-Path ${env:ProgramFiles(x86)} 'Microsoft Visual Studio/Installer/vswhere.exe'
    if (Test-Path -LiteralPath $vswhere -PathType Leaf) {
        $cmake = & $vswhere -products '*' -latest -find 'Common7\IDE\CommonExtensions\Microsoft\CMake\CMake\bin\cmake.exe' | Select-Object -First 1
    }
}
if (!$cmake) { throw 'CMake 3.20 or newer is required.' }
$stage = Join-Path ([IO.Path]::GetTempPath()) ('codex-apdu-gateway-native-' + [Guid]::NewGuid().ToString('N'))
if ($stage -match '[^\x00-\x7F]') { throw 'Use an ASCII-only temporary directory for CMake.' }
New-Item -ItemType Directory -Path $stage | Out-Null
& tar.exe -xf $archive -C $stage
if ($LASTEXITCODE -ne 0) { throw 'Mbed TLS extraction failed.' }
$native = Join-Path $stage 'native'
$source = Join-Path $stage 'mbedtls-3.6.8'
$build = Join-Path $stage 'build'
Copy-Item -LiteralPath $PSScriptRoot -Destination $native -Recurse
& $cmake -S $native -B $build "-DMBEDTLS_SOURCE=$source" '-DCMAKE_C_FLAGS=/utf-8' -A x64
if ($LASTEXITCODE -ne 0) { throw 'Native chip adapter configuration failed.' }
& $cmake --build $build --config Release --parallel 8
if ($LASTEXITCODE -ne 0) { throw 'Native chip adapter build failed.' }
foreach ($relative in @('target/debug', 'target/debug/deps')) {
    $destination = Join-Path $root $relative
    New-Item -ItemType Directory -Force -Path $destination | Out-Null
    Copy-Item -LiteralPath (Join-Path $build 'Release/codex-apdu-mbedtls.dll') -Destination $destination -Force
}
