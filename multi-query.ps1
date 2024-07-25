param (
    [string]$outfile
)

if (-not $outfile) {
    Write-Host "Usage: .\script.ps1 -outfile <path_to_output_file>"
    exit
}

function Get-ApiKeys {
    # Replace these with your primary and secondary API keys
    return @("API_KEY1", "API_KEY2")
}

function Query-VirusTotalApi {
    param (
        [string]$identifier,
        [string]$type,
        [int]$retryCount = 0
    )

    $apiKeys = Get-ApiKeys
    $apiKey = $apiKeys[$retryCount % $apiKeys.Count]

    if ($type -eq "hash") {
        $apiUrl = "https://www.virustotal.com/api/v3/files/$identifier"
    } elseif ($type -eq "ip") {
        $apiUrl = "https://www.virustotal.com/api/v3/ip_addresses/$identifier"
    }

    $headers = @{
        "x-apikey" = $apiKey
    }

    $quotaExceeded = $false
    try {
        $response = Invoke-RestMethod -Uri $apiUrl -Method Get -Headers $headers -ErrorAction Stop
    } catch [System.Net.WebException] {
        $webException = $_.Exception
        if ($webException.Response -and ($webException.Response -is [System.Net.HttpWebResponse])) {
            $statusCode = [int]$webException.Response.StatusCode
            if ($statusCode -eq 429) {
                $quotaExceeded = $true
            }
        }
    }

    if ($quotaExceeded -or ($response -and $response.error -and $response.error.code -eq "QuotaExceededError")) {
        if ($retryCount -lt $apiKeys.Count - 1) {
            Start-Sleep -Seconds 2  # Adding delay between requests
            return Query-VirusTotalApi -identifier $identifier -type $type -retryCount ($retryCount + 1)
        }
    }
    return $response
}

function Process-ApiResponse {
    param (
        [object]$response,
        [string]$identifier,
        [int]$processId,
        [string]$outfile,
        [string]$type
    )

    if ($response -eq $null) {
        $output = "Error querying: $($identifier), PID: $($processId)"
    } elseif ($response.data.attributes.last_analysis_stats.malicious -gt 0) {
        $output = "Malicious $type detected: $($identifier), PID: $($processId)"
    } else {
        $output = "$type is clean: $($identifier), PID: $($processId)"
    }

    $output | Out-File -Filepath $outfile -Append
}

function Get-ActiveProcessesHashes {
    $processes = Get-WmiObject Win32_Process | Where-Object { $_.ExecutablePath -ne $null } | Select-Object Name, ExecutablePath, ProcessId
    foreach ($process in $processes) {
        $hash = (Get-FileHash -Algorithm SHA256 -Path $process.ExecutablePath).Hash
        [PSCustomObject]@{
            Name            = $process.Name
            ExecutablePath  = $process.ExecutablePath
            ProcessId       = $process.ProcessId
            Hash            = $hash
        }
    }
}

function Get-ActiveConnections {
    Get-NetTCPConnection | Select-Object -Property RemoteAddress, OwningProcess -Unique
}

$processes = Get-ActiveProcessesHashes

foreach ($process in $processes) {
    $hash = $process.Hash
    $processId = $process.ProcessId
    $response = Query-VirusTotalApi -identifier $hash -type "hash"
    $null = Process-ApiResponse -response $response -identifier $hash -processId $processId -outfile $outfile -type "File hash"
    Start-Sleep -Seconds 1  # Adjust or remove
}

$activeConnections = Get-ActiveConnections

foreach ($connection in $activeConnections) {
    $ip = $connection.RemoteAddress
    $processId = $connection.OwningProcess
    $response = Query-VirusTotalApi -identifier $ip -type "ip"
    $null = Process-ApiResponse -response $response -identifier $ip -processId $processId -outfile $outfile -type "IP address"
    Start-Sleep -Seconds 1  # Adjust or remove
}
