#Requires -Version 7.0
param(
    [ValidateSet('deepseek', 'chatgpt')] [string] $Mode = 'chatgpt',
    [ValidatePattern('^[a-z0-9][a-z0-9_-]{0,31}$')] [string] $Alias = 'default',
    [switch] $Live,
    [switch] $Verify,
    [switch] $VerifyTools,
    [string] $Model,
    [string] $CodexExe
)
$ErrorActionPreference = 'Stop'
if ($VerifyTools -and $Live) { throw 'The deterministic tool test requires the offline fixture.' }
if (!$PSBoundParameters.ContainsKey('Mode') -and !$Verify -and !$VerifyTools) {
    if ([Console]::IsInputRedirected) { throw '请在交互终端选择模式，或通过 -Mode 指定服务。' }
    $choices = [ordered]@{
        '1' = @{ Mode = 'chatgpt'; Live = $true; Label = 'ChatGPT（真实服务）' }
        '2' = @{ Mode = 'deepseek'; Live = $true; Label = 'DeepSeek（真实服务）' }
    }
    if (!$Live) {
        $choices['3'] = @{ Mode = 'chatgpt'; Live = $false; Label = 'ChatGPT（离线演示）' }
        $choices['4'] = @{ Mode = 'deepseek'; Live = $false; Label = 'DeepSeek（离线演示）' }
    }
    Write-Host '选择 Codex 使用的模型服务。真实服务会发送提示词并可能消耗额度。'
    foreach ($entry in $choices.GetEnumerator()) { Write-Host "  $($entry.Key). $($entry.Value.Label)" }
    Write-Host '  0. 退出'
    do {
        $choice = Read-Host '输入编号'
        if ($null -eq $choice -or $choice.Trim() -eq '0') { return }
        $selection = $choices[$choice.Trim()]
        if (!$selection) { Write-Host '请输入菜单中的编号。' }
    } until ($selection)
    $Mode = $selection.Mode
    $Live = $selection.Live
}
$root = $PSScriptRoot
if (!$CodexExe) {
    $CodexExe = (Get-Command codex -CommandType Application -ErrorAction SilentlyContinue | Select-Object -First 1).Source
    if (!$CodexExe -and $IsWindows) {
        $CodexExe = Get-AppxPackage -Name 'OpenAI.Codex' -ErrorAction SilentlyContinue |
            Where-Object InstallLocation |
            ForEach-Object { Join-Path $_.InstallLocation 'app/resources/codex.exe' } |
            Where-Object { Test-Path -LiteralPath $_ -PathType Leaf } |
            Select-Object -First 1
    }
    if (!$CodexExe) { throw '找不到原版 Codex CLI。请安装 Codex，或用 -CodexExe 指定可执行文件。' }
}
$codex = (Resolve-Path -LiteralPath $CodexExe).Path
if ($codex -match '(?i)[\\/]codex-apdu[\\/]') { throw 'Use an unmodified Codex CLI executable.' }
if (!$Model) {
    $Model = if (!$Live) { 'gpt-5.4' } elseif ($Mode -eq 'deepseek') { 'deepseek-flash' } else { 'apdu-chatgpt-auto' }
}
$suffix = if ($IsWindows) { '.exe' } else { '' }
$gateway = (Resolve-Path -LiteralPath (Join-Path $root "target/debug/codex-apdu-gateway$suffix")).Path
$chip = (Resolve-Path -LiteralPath (Join-Path $root "target/debug/codex-apdu$suffix")).Path
$run = Join-Path $root ('.runtime/runs/' + [Guid]::NewGuid().ToString('N'))
$profiles = Join-Path $root '.runtime/profiles'
$clientHome = Join-Path $run 'codex-home'
$work = Join-Path $run 'work'
$bootstrap = Join-Path $run 'gateway.bootstrap'
New-Item -ItemType Directory -Force -Path $run,$clientHome,$work | Out-Null
if ($Live) { New-Item -ItemType Directory -Force -Path $profiles | Out-Null }
[IO.File]::WriteAllText($bootstrap, [Convert]::ToHexString([Security.Cryptography.RandomNumberGenerator]::GetBytes(32)))
$process = [Diagnostics.Process]::new()
$process.StartInfo.FileName = $gateway
$process.StartInfo.UseShellExecute = $false
$process.StartInfo.CreateNoWindow = $true
$process.StartInfo.RedirectStandardOutput = $true
$process.StartInfo.RedirectStandardError = $true
$data = if ($Live) { $profiles } else { $run }
foreach ($arg in @('serve', $Mode, $Alias, $Model, $bootstrap, $data)) { $process.StartInfo.ArgumentList.Add($arg) }
if (!$Live) { $process.StartInfo.ArgumentList.Add('offline') }
$process.StartInfo.Environment['CODEX_APDU_HELPER'] = $chip
$process.StartInfo.Environment['CODEX_APDU_CHATGPT_PROFILE'] = Join-Path $profiles 'ChatGPT'
$process.StartInfo.Environment['CODEX_APDU_CHATGPT_ALIAS'] = $Alias
$process.StartInfo.Environment['CODEX_APDU_LIVE_PROFILE'] = Join-Path $profiles 'DeepSeek'
$process.StartInfo.Environment['CODEX_APDU_LIVE_ALIAS'] = $Alias
$environment = @{ CODEX_HOME = $clientHome; CODEX_SQLITE_HOME = $clientHome; OPENAI_API_KEY = $null; CODEX_API_KEY = $null; CODEX_RS_SSE_FIXTURE = $null; NO_PROXY = (@($env:NO_PROXY, '127.0.0.1', 'localhost') -join ',') }
$previous = @{}
foreach ($name in $environment.Keys) { $previous[$name] = [Environment]::GetEnvironmentVariable($name, 'Process') }
$started = $false
$gatewayLog = Join-Path $run 'gateway.log'
$logStream = [IO.File]::Open($gatewayLog, [IO.FileMode]::CreateNew, [IO.FileAccess]::Write, [IO.FileShare]::ReadWrite)
$capture = $null

function Invoke-CodexVerification([string[]] $Arguments, [string] $LogPath) {
    $probe = [Diagnostics.Process]::new()
    $probe.StartInfo.FileName = $codex
    $probe.StartInfo.UseShellExecute = $false
    $probe.StartInfo.CreateNoWindow = $true
    $probe.StartInfo.RedirectStandardInput = $true
    $probe.StartInfo.RedirectStandardOutput = $true
    $probe.StartInfo.RedirectStandardError = $true
    $probe.StartInfo.StandardOutputEncoding = [Text.Encoding]::UTF8
    $probe.StartInfo.StandardErrorEncoding = [Text.Encoding]::UTF8
    foreach ($arg in @('-C', $work, 'exec', '--skip-git-repo-check', '--color', 'never') + $Arguments) {
        $probe.StartInfo.ArgumentList.Add($arg)
    }
    try {
        [void]$probe.Start()
        $probe.StandardInput.Close()
        $out = $probe.StandardOutput.ReadToEndAsync()
        $err = $probe.StandardError.ReadToEndAsync()
        $timeout = if ($Live) { 240000 } else { 45000 }
        $finished = $probe.WaitForExit($timeout)
        if (!$finished) { $probe.Kill($true); $probe.WaitForExit() }
        [IO.File]::AppendAllText($LogPath, $err.GetAwaiter().GetResult())
        if (!$finished) { throw "Codex verification timed out. See $LogPath" }
        if ($probe.ExitCode -ne 0) { throw "Codex verification exited with $($probe.ExitCode). See $LogPath" }
        return $out.GetAwaiter().GetResult()
    } finally {
        $probe.Dispose()
    }
}

try {
    $started = $process.Start()
    $capture = $process.StandardError.BaseStream.CopyToAsync($logStream)
    $read = $process.StandardOutput.ReadLineAsync()
    if (!$read.Wait(10000)) { throw 'The gateway did not start within 10 seconds.' }
    $address = $read.Result
    if ($address -notmatch '^127\.0\.0\.1:[0-9]+$') { throw 'The gateway did not report its local address.' }
    $config = Get-Content -Raw -LiteralPath (Join-Path $root 'config.toml.template')
    foreach ($pair in @{ MODEL = $Model; BASE_URL = "http://$address/v1"; HELPER = $gateway; ADDRESS = $address; BOOTSTRAP = $bootstrap }.GetEnumerator()) {
        $config = $config.Replace("__$($pair.Key)__", (ConvertTo-Json -InputObject $pair.Value -Compress))
    }
    $projectKey = ConvertTo-Json -InputObject $work -Compress
    [IO.File]::WriteAllText((Join-Path $clientHome 'config.toml'), "$config`n[projects.$projectKey]`ntrust_level = 'untrusted'`n")
    foreach ($name in $environment.Keys) { [Environment]::SetEnvironmentVariable($name, ($environment[$name] ?? [NullString]::Value), 'Process') }
    $version = & $codex --version
    if ($LASTEXITCODE -ne 0 -or !$version) { throw 'Could not determine the official Codex CLI version.' }
    Write-Host "$version | $Mode | $run"
    if ($Live) {
        if ($Mode -eq 'chatgpt') { Write-Host 'If the browser opens, complete the official ChatGPT sign-in.' }
        & $gateway credential $address $bootstrap | Out-Null
        if ($LASTEXITCODE -ne 0) { throw "Chip authorization failed. See $gatewayLog" }
    }
    if (!$Verify -and !$VerifyTools) {
        $clientArgs = @('-C', $work)
        if ((& $codex --help 2>$null) -match '(^|\s)--no-daemon(\s|$)') { $clientArgs += '--no-daemon' }
        & $codex @clientArgs
        if ($LASTEXITCODE -ne 0) { throw "Codex exited with code $LASTEXITCODE." }
        return
    }
    $log = Join-Path $run 'codex-exec.log'
    if ($Live) {
        $firstReply = Invoke-CodexVerification @('记住本次测试标记 APDU_E2E_OK，并原样回复该标记。') $log
        if ($firstReply -notlike '*APDU_E2E_OK*') { throw 'First live Responses request failed.' }
        $secondReply = Invoke-CodexVerification @('resume','--last','请原样回复我上一轮提供的测试标记。') $log
        if ($secondReply -notlike '*APDU_E2E_OK*') { throw 'Live conversation continuation failed.' }
        Write-Host "Verified two live Codex turns in $Mode mode."
        return
    }
    $first = '网关第一轮分片测试🙂' * 32
    $second = '网关第二轮，上一次说了什么？'
    $reply = '离线模型响应：已通过 APDU 收到模型请求。'
    $requestsFile = Join-Path $run 'model-requests.jsonl'
    if ($VerifyTools) {
        $output = Invoke-CodexVerification @('APDU_GATEWAY_TOOL_TEST') $log
        if ($output -notlike "*$reply*") { throw "Tool verification reply missing. See $log" }
        $events = @(Get-Content -LiteralPath $requestsFile -Encoding utf8 | ForEach-Object { ConvertFrom-Json -InputObject $_ })
        $callResults = @($events[1].input | Where-Object { $_.type -eq 'function_call_output' -and $_.call_id -eq 'call_apdu_fixture_plan' })
        if ($events.Length -ne 2 -or $callResults.Length -ne 1 -or !$callResults[0].output) { throw 'The model did not receive the expected tool output.' }
        Write-Host 'Verified a stock Codex tool call and its output over HTTP/SSE, APDU and local TLS.'
        return
    }
    $output = Invoke-CodexVerification @($first) $log
    if ($output -notlike "*$reply*") { throw "First reply missing. See $log" }
    $output = Invoke-CodexVerification @('resume','--last',$second) $log
    if ($output -notlike "*$reply*") { throw "Second reply missing. See $log" }
    $requests = @(Get-Content -LiteralPath $requestsFile -Encoding utf8 | ForEach-Object { ConvertFrom-Json -InputObject $_ })
    if ($requests.Length -ne 2) { throw "Expected two model requests, got $($requests.Length)." }
    $firstText = @($requests[0].input | Where-Object role -eq user | ForEach-Object { $_.content.text })
    $followupText = @($requests[1].input | Where-Object role -eq user | ForEach-Object { $_.content.text })
    $previousReply = @($requests[1].input | Where-Object role -eq assistant | ForEach-Object { $_.content.text })
    if ($first -cnotin $firstText -or $first -cnotin $followupText -or $second -cnotin $followupText -or $reply -cnotin $previousReply) {
        throw 'Unicode or multi-turn context did not arrive intact.'
    }
    $testKey = [IO.File]::ReadAllText((Join-Path $run 'fixture/chip/api-key'))
    if (Select-String -LiteralPath $log,$requestsFile,$gatewayLog,(Join-Path $clientHome 'config.toml') -Pattern $testKey -SimpleMatch -Quiet) { throw 'Upstream test key found outside its expected boundary.' }
    Write-Host "Verified $Mode over stock Codex, HTTP/SSE, APDU and local TLS. First prompt UTF-8 bytes: $([Text.Encoding]::UTF8.GetByteCount($first))."
} finally {
    if ($started -and !$process.HasExited) { $process.Kill(); $process.WaitForExit() }
    if ($capture) { [void]$capture.GetAwaiter().GetResult() }
    $logStream.Dispose()
    $process.Dispose()
    if (Test-Path -LiteralPath $bootstrap -PathType Leaf) { Remove-Item -LiteralPath $bootstrap }
    foreach ($name in $previous.Keys) { [Environment]::SetEnvironmentVariable($name, ($previous[$name] ?? [NullString]::Value), 'Process') }
}
