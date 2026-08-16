<#
.SYNOPSIS
    Aligns Windows Firewall rules with the MedDefense segmentation contract.
#>

$ErrorActionPreference = "Stop"

$RulesFile = "segmentation_rules.json"
$OutputFile = "windows_firewall_export.json"

if (-not (Test-Path $RulesFile)) {
    Write-Error "Error: Missing segmentation rules file: $RulesFile"
    exit 1
}

Write-Host "[*] Reading $RulesFile..." -ForegroundColor Cyan
$Contract = Get-Content -Path $RulesFile | ConvertFrom-Json

Write-Host "[*] Setting profile defaults..." -ForegroundColor Cyan
$Profiles = @("Domain", "Private", "Public")
$LogPath = "$env:systemroot\system32\LogFiles\Firewall\meddefense.log"

$LogDir = Split-Path -Parent $LogPath
if (-not (Test-Path $LogDir)) {
    New-Item -ItemType Directory -Force -Path $LogDir | Out-Null
}

foreach ($Profile in $Profiles) {
    Set-NetFirewallProfile -Profile $Profile -DefaultInboundAction Block -DefaultOutboundAction Allow -LogBlocked True -LogFileName $LogPath
    Write-Host "  $Profile`:  DefaultInboundAction=Block  LogBlocked=True   [SET]"
}

Write-Host "[*] Clearing previous MedDefense-* rules..." -NoNewline
$ExistingRules = Get-NetFirewallRule -DisplayName "MedDefense-*" -ErrorAction SilentlyContinue
$RemovedCount = 0
if ($ExistingRules) {
    $RemovedCount = @($ExistingRules).Count
    $ExistingRules | Remove-NetFirewallRule
}
Write-Host "              [$RemovedCount removed]" -ForegroundColor Green

Write-Host "[*] Creating rules from flow matrix..." -ForegroundColor Cyan

$ZoneMap = @{}
foreach ($Zone in $Contract.zones) {
    $ZoneMap[$Zone.name] = $Zone.cidr
}

foreach ($Flow in $Contract.flows) {
    if ($Flow.action -eq "deny_all") {
        continue
    }

    $SrcZone = $Flow.src_zone
    $Proto = $Flow.proto
    $DPort = $Flow.dport

    $RemoteAddr = if ($ZoneMap.ContainsKey($SrcZone)) { $ZoneMap[$SrcZone] } else { "Any" }
    
    $DisplayName = "MedDefense-$SrcZone-$($Proto.ToUpper())-$DPort"

    New-NetFirewallRule -DisplayName $DisplayName `
                        -Direction Inbound `
                        -Action Allow `
                        -Protocol $Proto `
                        -LocalPort $DPort `
                        -RemoteAddress $RemoteAddr `
                        -Profile Any | Out-Null

    Write-Host "  $DisplayName".PadEnd(30) -NoNewline
    Write-Host "Inbound Allow $Proto $DPort" -NoNewline
    Write-Host "    [CREATED]" -ForegroundColor Green
}

Write-Host "[*] Exporting resulting rules as JSON..." -ForegroundColor Cyan
$ExportRules = Get-NetFirewallRule -DisplayName "MedDefense-*" | Get-NetFirewallPortFilter | Select-Object PSComputerName, CreationClassName, SystemName, SystemCreationClassName, Name, Protocol, LocalPort, RemotePort | ConvertTo-Json
$ExportRules | Out-File -FilePath $OutputFile -Encoding utf8
Write-Host "  Exported to $OutputFile" -ForegroundColor Green
