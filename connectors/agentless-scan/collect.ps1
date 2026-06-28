<#
  collect.ps1 — XORCISM agentless host collector (Windows).

  Emits a JSON host snapshot (OS, installed software, hotfixes, listening ports, a few CIS-style baseline
  checks) for the `agentless-scan` connector. No agent, read-only, no data leaves the host until YOU move it.

    Local / air-gapped ("mode deconnecte"):  powershell -ExecutionPolicy Bypass -File collect.ps1 > snapshot.json
    Over an admin WinRM session (agentless):  Invoke-Command -ComputerName host -FilePath collect.ps1 |
                                                ConvertTo-Json -Depth 6 > snapshot.json

  Then import:  python connectors/runner.py --connector agentless-scan --file snapshot.json
#>
$ErrorActionPreference = 'SilentlyContinue'

$os = Get-CimInstance Win32_OperatingSystem
$osName = if ($os.ProductType -eq 1) { 'windows' } else { 'windows_server' }
# normalise "Microsoft Windows Server 2019 ..." version → release number
$osVer  = ($os.Caption -replace '[^0-9]', ' ').Trim() -split '\s+' | Where-Object { $_ } | Select-Object -First 1

# installed software from the uninstall registry hives (both 32/64-bit)
$paths = @(
  'HKLM:\SOFTWARE\Microsoft\Windows\CurrentVersion\Uninstall\*',
  'HKLM:\SOFTWARE\WOW6432Node\Microsoft\Windows\CurrentVersion\Uninstall\*'
)
$packages = foreach ($p in $paths) {
  Get-ItemProperty $p | Where-Object { $_.DisplayName } | ForEach-Object {
    [pscustomobject]@{ name = $_.DisplayName; version = ([string]$_.DisplayVersion) }
  }
}
$packages = $packages | Sort-Object name -Unique

# hotfixes (so missing-patch / superseded analysis has the KB baseline)
$hotfix = Get-HotFix | ForEach-Object { [pscustomobject]@{ name = $_.HotFixID; version = '' } }

# listening TCP ports
$listening = Get-NetTCPConnection -State Listen |
  Select-Object -ExpandProperty LocalPort -Unique |
  ForEach-Object { [pscustomobject]@{ port = $_; proto = 'tcp' } }

# a few CIS-style baseline checks
function New-Check($id, $title, $result, $severity) { [pscustomobject]@{ id = $id; title = $title; result = $result; severity = $severity } }
$checks = @()

$smb1 = (Get-WindowsOptionalFeature -Online -FeatureName SMB1Protocol).State
$checks += New-Check 'smbv1-disabled' 'SMBv1 protocol disabled' ($(if ($smb1 -eq 'Enabled') { 'fail' } else { 'pass' })) 'high'

$nla = (Get-ItemProperty 'HKLM:\SYSTEM\CurrentControlSet\Control\Terminal Server\WinStations\RDP-Tcp').UserAuthentication
$checks += New-Check 'rdp-nla' 'RDP Network Level Authentication required' ($(if ($nla -eq 1) { 'pass' } else { 'fail' })) 'high'

$fw = Get-NetFirewallProfile | Where-Object { -not $_.Enabled }
$checks += New-Check 'host-firewall' 'Windows Firewall enabled on all profiles' ($(if ($fw) { 'fail' } else { 'pass' })) 'medium'

$rt = (Get-MpPreference).DisableRealtimeMonitoring
$checks += New-Check 'defender-realtime' 'Defender real-time protection enabled' ($(if ($rt) { 'fail' } else { 'pass' })) 'medium'

[pscustomobject]@{
  hostname  = $env:COMPUTERNAME
  ip        = (Get-NetIPAddress -AddressFamily IPv4 | Where-Object { $_.IPAddress -notlike '127.*' } | Select-Object -First 1).IPAddress
  os        = [pscustomobject]@{ family = 'windows'; name = $osName; version = "$osVer"; kernel = $os.Version }
  packages  = @($packages) + @($hotfix)
  listening = @($listening)
  checks    = @($checks)
} | ConvertTo-Json -Depth 6
