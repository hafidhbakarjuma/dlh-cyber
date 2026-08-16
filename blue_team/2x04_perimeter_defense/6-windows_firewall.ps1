<#
.SYNOPSIS
    Aligns Windows Firewall rules with the MedDefense segmentation contract.
#>

$ErrorActionPreference = "Stop"

$RulesFile = "segmentation_rules.json"

if (-not (Test-Path $RulesFile)) {
    Write-Error "Error: Missing segmentation rules file: $RulesFile"
    exit 1
}

Write-Host "[*] Reading $RulesFile..." -ForegroundColor Cyan
$Contract = Get-Content -Path $RulesFile | ConvertFrom-Json

Write-Host "[*] Setting profile defaults..." -ForegroundColor Cyan
$Profiles = @("Domain", "Private", "Public")
$LogPath = "$env:systemroot\system32\LogFiles\Firewall\meddefense.log"

# Ensure log directory exists
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

# Map zone names to their respective CIDRs from the zones array
$ZoneMap = @{}
foreach ($Zone in $Contract.zones) {
    $ZoneMap[$Zone.name] = $Zone.cidr
}

# Process inbound rules targeting this host based on the flow matrix
foreach ($Flow in $Contract.flows) {
    # Skip cross-zone forward-only flows unless they terminate locally or are specifically required inbound
    if ($Flow.action -eq "deny_all") {
        continue
    }

    $SrcZone = $Flow.src_zone
    $Proto = $Flow.proto
    $DPort = $Flow.dport

    # Determine remote address based on source zone CIDR (default to Any if ALL)
    $RemoteAddr = if ($ZoneMap.ContainsKey($SrcZone)) { $ZoneMap[$SrcZone] } else { "Any" }
    
    $DisplayName = "MedDefense-$SrcZone-$($Proto.ToUpper())-$DPort"

    # Create the inbound rule
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
