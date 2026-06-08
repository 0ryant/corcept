param(
    [string]$ProtocolVersion = "2025-11-25",
    [string]$TargetDir = ""
)

$ErrorActionPreference = "Stop"

function Send-McpMessage {
    param(
        [System.IO.StreamWriter]$Writer,
        [hashtable]$Message
    )

    $json = $Message | ConvertTo-Json -Compress -Depth 20
    $Writer.WriteLine($json)
    $Writer.Flush()
}

function Receive-McpMessage {
    param([System.IO.StreamReader]$Reader)

    $line = $Reader.ReadLine()
    if ([string]::IsNullOrWhiteSpace($line)) {
        throw "Expected MCP response line but received EOF or blank output."
    }
    try {
        return $line | ConvertFrom-Json
    }
    catch {
        throw "Expected MCP JSON response but received: $line"
    }
}

$repoRoot = Resolve-Path (Join-Path $PSScriptRoot "..")
$packageRoot = Join-Path $repoRoot "crates\corcept-mcp"
if ([string]::IsNullOrWhiteSpace($TargetDir)) {
    $TargetDir = Join-Path $repoRoot "target\canonical-mcp"
}

$oldCargoTargetDir = $env:CARGO_TARGET_DIR
$oldPath = $env:PATH
$runRoot = Join-Path $repoRoot ("target\canonical-mcp-run-" + [guid]::NewGuid().ToString("N"))
$process = $null

try {
    $env:CARGO_TARGET_DIR = $TargetDir
    cargo build -p corcept-cli -p corcept-mcp | Out-Host
    if ($LASTEXITCODE -ne 0) {
        throw "cargo build failed."
    }

    $exe = if ($IsWindows) { ".exe" } else { "" }
    $binDir = Join-Path $TargetDir "debug"
    $corcept = Join-Path $binDir "corcept$exe"
    $corceptMcp = Join-Path $binDir "corcept-mcp$exe"
    foreach ($binary in @($corcept, $corceptMcp)) {
        if (-not (Test-Path $binary)) {
            throw "Expected binary not found: $binary"
        }
    }

    New-Item -ItemType Directory -Path (Join-Path $runRoot ".mcpact") -Force | Out-Null
    Copy-Item -LiteralPath (Join-Path $packageRoot ".mcpact\mcpact.lock") -Destination (Join-Path $runRoot ".mcpact\mcpact.lock")

    $projectRoot = Join-Path $runRoot "project"
    & $corcept init --path $projectRoot | Out-Null
    if ($LASTEXITCODE -ne 0) {
        throw "corcept init failed."
    }

    $env:PATH = "$binDir$([System.IO.Path]::PathSeparator)$oldPath"

    $process = New-Object System.Diagnostics.Process
    $process.StartInfo.FileName = $corceptMcp
    $process.StartInfo.WorkingDirectory = $runRoot
    $process.StartInfo.UseShellExecute = $false
    $process.StartInfo.RedirectStandardInput = $true
    $process.StartInfo.RedirectStandardOutput = $true
    $process.StartInfo.RedirectStandardError = $true
    $process.StartInfo.CreateNoWindow = $true
    $null = $process.Start()

    $stdin = $process.StandardInput
    $stdout = $process.StandardOutput

    Send-McpMessage $stdin @{
        jsonrpc = "2.0"
        id = 1
        method = "initialize"
        params = @{
            protocolVersion = $ProtocolVersion
            capabilities = @{}
            clientInfo = @{
                name = "corcept-canonical-smoke"
                version = "0.1.0"
            }
        }
    }
    $initialize = Receive-McpMessage $stdout
    if ($initialize.result.protocolVersion -ne $ProtocolVersion) {
        throw "Unexpected protocol version: $($initialize.result.protocolVersion)"
    }
    if ($initialize.result.serverInfo.name -ne "mcpact-generated") {
        throw "Unexpected server name: $($initialize.result.serverInfo.name)"
    }

    Send-McpMessage $stdin @{
        jsonrpc = "2.0"
        method = "notifications/initialized"
    }

    Send-McpMessage $stdin @{
        jsonrpc = "2.0"
        id = 2
        method = "tools/list"
        params = @{}
    }
    $tools = Receive-McpMessage $stdout
    $toolNames = @($tools.result.tools | ForEach-Object { $_.name })
    foreach ($expected in @(
        "corcept_audit_verify",
        "corcept_doctor",
        "corcept_export_cloudevents",
        "corcept_hook_posttool_audit",
        "corcept_hook_pretool_guard",
        "corcept_hook_session_start",
        "corcept_hook_stop_check",
        "corcept_hook_user_prompt_submit",
        "corcept_key_generate"
    )) {
        if ($toolNames -notcontains $expected) {
            throw "Missing expected canonical MCP tool: $expected"
        }
    }

    Send-McpMessage $stdin @{
        jsonrpc = "2.0"
        id = 3
        method = "tools/call"
        params = @{
            name = "corcept_doctor"
            arguments = @{
                path = $projectRoot
                strict = $true
            }
        }
    }
    $doctor = Receive-McpMessage $stdout
    if ($doctor.result.isError) {
        throw "corcept_doctor returned an MCP error: $($doctor.result.content[0].text)"
    }
    if ($doctor.result.structuredContent.status -ne "pass") {
        throw "corcept_doctor did not pass: $($doctor.result.content[0].text)"
    }

    $stdin.Close()
    if (-not $process.WaitForExit(5000)) {
        $process.Kill()
        throw "corcept-mcp did not exit cleanly after stdin close."
    }
    if ($process.ExitCode -ne 0) {
        throw "corcept-mcp exited with code $($process.ExitCode): $($process.StandardError.ReadToEnd())"
    }

    Write-Host "Canonical MCP smoke passed for $corceptMcp"
}
finally {
    if ($null -ne $process -and -not $process.HasExited) {
        try {
            $process.Kill()
            $process.WaitForExit(5000) | Out-Null
        }
        catch {
            Write-Warning "Could not terminate corcept-mcp smoke process: $_"
        }
    }
    $env:CARGO_TARGET_DIR = $oldCargoTargetDir
    $env:PATH = $oldPath
    if (Test-Path $runRoot) {
        for ($attempt = 1; $attempt -le 5; $attempt++) {
            try {
                Remove-Item -LiteralPath $runRoot -Recurse -Force
                break
            }
            catch {
                if ($attempt -eq 5) {
                    Write-Warning "Could not remove smoke run directory ${runRoot}: $_"
                }
                else {
                    Start-Sleep -Milliseconds 250
                }
            }
        }
    }
}
