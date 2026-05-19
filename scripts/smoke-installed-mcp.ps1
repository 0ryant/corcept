param(
    [string]$CorceptCommand = "corcept",
    [string]$ProtocolVersion = "2025-06-18"
)

$ErrorActionPreference = "Stop"

function Send-McpMessage {
    param(
        [System.IO.StreamWriter]$Writer,
        [hashtable]$Message
    )

    $json = $Message | ConvertTo-Json -Compress -Depth 10
    $Writer.WriteLine($json)
    $Writer.Flush()
}

function Receive-McpMessage {
    param([System.IO.StreamReader]$Reader)

    $line = $Reader.ReadLine()
    if ([string]::IsNullOrWhiteSpace($line)) {
        throw "Expected MCP response line but received EOF or blank output."
    }
    return $line | ConvertFrom-Json
}

function Invoke-CorceptWithStdin {
    param(
        [string]$FileName,
        [string]$Arguments,
        [string]$InputText
    )

    $process = New-Object System.Diagnostics.Process
    $process.StartInfo.FileName = $FileName
    $process.StartInfo.Arguments = $Arguments
    $process.StartInfo.UseShellExecute = $false
    $process.StartInfo.RedirectStandardInput = $true
    $process.StartInfo.RedirectStandardOutput = $true
    $process.StartInfo.RedirectStandardError = $true
    $process.StartInfo.CreateNoWindow = $true
    $null = $process.Start()
    $process.StandardInput.Write($InputText)
    $process.StandardInput.Close()
    $stdout = $process.StandardOutput.ReadToEnd()
    $stderr = $process.StandardError.ReadToEnd()
    $process.WaitForExit()
    if ($process.ExitCode -ne 0) {
        throw "Command failed: $FileName $Arguments`n$stderr"
    }
    return $stdout
}

$corcept = Get-Command $CorceptCommand -ErrorAction Stop
$tempRoot = Join-Path ([System.IO.Path]::GetTempPath()) ("corcept-mcp-smoke-" + [guid]::NewGuid().ToString("N"))
New-Item -ItemType Directory -Path $tempRoot | Out-Null

try {
    & $corcept.Source init --path $tempRoot | Out-Null
    & $corcept.Source memory propose --path $tempRoot --title "Convention" --claim "Use explicit errors" --evidence "src/lib.rs:10" | Out-Null

    $hookInput = @{
        session_id = "smoke-1"
        cwd = $tempRoot
        hook_event_name = "SessionStart"
    } | ConvertTo-Json -Compress
    Invoke-CorceptWithStdin -FileName $corcept.Source -Arguments "hook session-start" -InputText $hookInput | Out-Null
    $lastHashPath = Join-Path $tempRoot ".corcept\\ledger\\last_hash"
    if (Test-Path $lastHashPath) {
        Remove-Item -LiteralPath $lastHashPath -Force
    }

    $process = New-Object System.Diagnostics.Process
    $process.StartInfo.FileName = $corcept.Source
    $process.StartInfo.Arguments = "serve --path `"$tempRoot`""
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
                name = "corcept-smoke"
                version = "0.1.0"
            }
        }
    }
    $initialize = Receive-McpMessage $stdout
    if ($initialize.result.protocolVersion -ne $ProtocolVersion) {
        throw "Unexpected protocol version: $($initialize.result.protocolVersion)"
    }

    Send-McpMessage $stdin @{
        jsonrpc = "2.0"
        method = "notifications/initialized"
    }

    Send-McpMessage $stdin @{
        jsonrpc = "2.0"
        id = 2
        method = "tools/list"
    }
    $tools = Receive-McpMessage $stdout
    $toolNames = @($tools.result.tools | ForEach-Object { $_.name })
    foreach ($expected in @("doctor_report", "audit_report", "doctrine_validate", "candidate_memory_list", "cloudevents_preview")) {
        if ($toolNames -notcontains $expected) {
            throw "Missing expected MCP tool: $expected"
        }
    }

    Send-McpMessage $stdin @{
        jsonrpc = "2.0"
        id = 3
        method = "tools/call"
        params = @{
            name = "doctor_report"
            arguments = @{
                strict = $true
            }
        }
    }
    $doctor = Receive-McpMessage $stdout
    if ($doctor.result.structuredContent.status -ne "pass") {
        throw "doctor_report did not pass."
    }
    if (Test-Path $lastHashPath) {
        throw "doctor_report recreated ledger sidecar state."
    }

    Send-McpMessage $stdin @{
        jsonrpc = "2.0"
        id = 4
        method = "tools/call"
        params = @{
            name = "candidate_memory_list"
            arguments = @{
                limit = 5
            }
        }
    }
    $candidates = Receive-McpMessage $stdout
    if ([int]$candidates.result.structuredContent.count -lt 1) {
        throw "candidate_memory_list returned no candidates."
    }

    Send-McpMessage $stdin @{
        jsonrpc = "2.0"
        id = 5
        method = "tools/call"
        params = @{
            name = "cloudevents_preview"
            arguments = @{
                limit = 1
            }
        }
    }
    $preview = Receive-McpMessage $stdout
    if ([int]$preview.result.structuredContent.preview_count -lt 1) {
        throw "cloudevents_preview returned no derived events."
    }
    if (Test-Path $lastHashPath) {
        throw "read-only MCP calls recreated ledger sidecar state."
    }

    $stdin.Close()
    if (-not $process.WaitForExit(5000)) {
        $process.Kill()
        throw "corcept serve did not exit cleanly after stdin close."
    }
    if ($process.ExitCode -ne 0) {
        throw "corcept serve exited with code $($process.ExitCode): $($process.StandardError.ReadToEnd())"
    }

    $emptyRoot = Join-Path ([System.IO.Path]::GetTempPath()) ("corcept-mcp-empty-" + [guid]::NewGuid().ToString("N"))
    New-Item -ItemType Directory -Path $emptyRoot | Out-Null
    try {
        $emptyProcess = New-Object System.Diagnostics.Process
        $emptyProcess.StartInfo.FileName = $corcept.Source
        $emptyProcess.StartInfo.Arguments = "serve --path `"$emptyRoot`""
        $emptyProcess.StartInfo.UseShellExecute = $false
        $emptyProcess.StartInfo.RedirectStandardInput = $true
        $emptyProcess.StartInfo.RedirectStandardOutput = $true
        $emptyProcess.StartInfo.RedirectStandardError = $true
        $emptyProcess.StartInfo.CreateNoWindow = $true
        $null = $emptyProcess.Start()

        $emptyStdin = $emptyProcess.StandardInput
        $emptyStdout = $emptyProcess.StandardOutput

        Send-McpMessage $emptyStdin @{
            jsonrpc = "2.0"
            id = 11
            method = "initialize"
            params = @{
                protocolVersion = $ProtocolVersion
                capabilities = @{}
                clientInfo = @{
                    name = "corcept-smoke-empty"
                    version = "0.1.0"
                }
            }
        }
        $null = Receive-McpMessage $emptyStdout
        Send-McpMessage $emptyStdin @{
            jsonrpc = "2.0"
            method = "notifications/initialized"
        }
        Send-McpMessage $emptyStdin @{
            jsonrpc = "2.0"
            id = 12
            method = "tools/call"
            params = @{
                name = "candidate_memory_list"
                arguments = @{
                    limit = 5
                }
            }
        }
        $emptyCandidates = Receive-McpMessage $emptyStdout
        if ([int]$emptyCandidates.result.structuredContent.count -ne 0) {
            throw "candidate_memory_list on empty root should return zero candidates."
        }
        if (Test-Path (Join-Path $emptyRoot ".corcept\\memory")) {
            throw "candidate_memory_list created .corcept/memory on an empty root."
        }

        $emptyStdin.Close()
        if (-not $emptyProcess.WaitForExit(5000)) {
            $emptyProcess.Kill()
            throw "empty-root corcept serve did not exit cleanly after stdin close."
        }
        if ($emptyProcess.ExitCode -ne 0) {
            throw "empty-root corcept serve exited with code $($emptyProcess.ExitCode): $($emptyProcess.StandardError.ReadToEnd())"
        }
    }
    finally {
        if (Test-Path $emptyRoot) {
            Remove-Item -LiteralPath $emptyRoot -Recurse -Force
        }
    }

    Write-Host "Installed MCP smoke passed for $($corcept.Source)"
}
finally {
    if (Test-Path $tempRoot) {
        Remove-Item -LiteralPath $tempRoot -Recurse -Force
    }
}
