param (
    [string]$filePath
)

if (-not $filePath) {
    Write-Host "Usage: .\script.ps1 -filePath <path_to_output_file>"
    exit
}

function Get-ApiKey {
    # Replace this with your API key
    return "API_KEY"
}

function Query-VirusTotalApi {
    param (
        [string]$ip
    )

    $apiKey = Get-ApiKey
    $apiUrl = "https://www.virustotal.com/api/v3/ip_addresses/$ip"
    $headers = @{
        "x-apikey" = $apiKey
    }

    $response = Invoke-RestMethod -Uri $apiUrl -Method Get -Headers $headers
    return $response
}

function Process-ApiResponse {
    param (
        [object]$response,
        [string]$ip,
        [int]$processId,
        [string]$filePath
    )

    if ($response.data.attributes.last_analysis_stats.malicious -gt 0) {
        $output = "Malicious IP detected: $ip, PID: $processId"
    } else {
        $output = "IP is clean: $ip, PID: $processId"
    }

    $output | Out-File -FilePath $filePath -Append
}

$activeConnections = Get-NetTCPConnection | Select-Object -Property RemoteAddress, OwningProcess -Unique

foreach ($connection in $activeConnections) {
    $ip = $connection.RemoteAddress
    $processId = $connection.OwningProcess
    $response = Query-VirusTotalApi -ip $ip
    $null = Process-ApiResponse -response $response -ip $ip -processId $processId -filePath $filePath
}
