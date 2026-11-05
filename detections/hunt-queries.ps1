# Lab 2 hunts — use New Logon Properties indices for 4624.
# Message first-match on "Account Name" / "Logon ID" hits Subject ("-" / 0x0).
#
# 4624: [5]=TargetUserName [7]=TargetLogonId [8]=LogonType
#       [10]=AuthenticationPackageName [18]=IpAddress [19]=IpPort
# 4672: [1]=SubjectUserName [3]=SubjectLogonId [4]=PrivilegeList

# --- 1) Remote NTLM Type 3 logons (non-machine, non-anonymous) ---
Get-WinEvent -FilterHashtable @{LogName='Security'; Id=4624; StartTime=(Get-Date).AddMinutes(-30)} |
  Where-Object {
    $_.Properties[8].Value -eq 3 -and
    $_.Properties[10].Value -match 'NTLM' -and
    $_.Properties[5].Value -notlike '*$' -and
    $_.Properties[5].Value -ne 'ANONYMOUS LOGON'
  } |
  ForEach-Object {
    [PSCustomObject]@{
      Time       = $_.TimeCreated
      Account    = $_.Properties[5].Value
      Domain     = $_.Properties[6].Value
      LogonId    = $_.Properties[7].Value
      SourceIP   = $_.Properties[18].Value
      SourcePort = $_.Properties[19].Value
      AuthPkg    = $_.Properties[10].Value
    }
  } |
  Format-Table -AutoSize

# --- 2) Correlate 4624 -> 4672 by New Logon Logon ID ---
# Repeated NetExec connections => many Logon IDs; count distinct sessions.
$start = Get-Date '2026-11-05 18:38:00'
$end   = Get-Date '2026-11-05 18:46:00'

$logons = Get-WinEvent -FilterHashtable @{LogName='Security'; Id=4624; StartTime=$start; EndTime=$end} |
  Where-Object {
    $_.Properties[8].Value -eq 3 -and
    $_.Properties[5].Value -eq 'soclab1' -and
    $_.Properties[18].Value -eq '192.168.56.101'
  }

foreach ($e in $logons) {
  $lid = $e.Properties[7].Value
  $priv = Get-WinEvent -FilterHashtable @{LogName='Security'; Id=4672; StartTime=$start; EndTime=$end} |
    Where-Object { $_.Properties[3].Value -eq $lid } |
    Select-Object -First 1
  [PSCustomObject]@{
    Time4624   = $e.TimeCreated
    LogonId    = $lid
    Has4672    = [bool]$priv
    PrivTime   = if ($priv) { $priv.TimeCreated } else { $null }
    HighImpact = if ($priv -and "$($priv.Properties[4].Value)" -match 'SeDebugPrivilege|SeBackupPrivilege|SeRestorePrivilege|SeTakeOwnershipPrivilege') { $true } else { $false }
  }
}

# --- 3) Inspect 4672 privileges for the documented correlation example ---
Get-WinEvent -FilterHashtable @{LogName='Security'; Id=4672; StartTime=$start; EndTime=$end} |
  Where-Object { "$($_.Properties[3].Value)" -match '1F2A10A' } |
  Format-List TimeCreated, Message

# --- 4) Process-creation checks (empty result ≠ proof of non-execution) ---
Get-WinEvent -FilterHashtable @{
  LogName='Security'; Id=4688; StartTime=$start; EndTime=$end
} -ErrorAction SilentlyContinue |
  Where-Object { $_.Message -match 'whoami|hostname|cmd\.exe' } |
  Format-List TimeCreated, Message

# Prefer a time-bounded query. A MaxEvents-first query can return only older
# WmiPrvSE starts and miss the attack window entirely.
Get-WinEvent -FilterHashtable @{
  LogName='Microsoft-Windows-Sysmon/Operational'; Id=1
  StartTime=$start; EndTime=$end
} -ErrorAction SilentlyContinue |
  Where-Object { $_.Message -match 'whoami|hostname|cmd\.exe|WmiPrvSE' } |
  Format-List TimeCreated, Message

# --- 5) Distinct remote Logon IDs per account/source (tooling burst) ---
Get-WinEvent -FilterHashtable @{LogName='Security'; Id=4624; StartTime=$start; EndTime=$end} |
  Where-Object {
    $_.Properties[8].Value -eq 3 -and
    $_.Properties[10].Value -match 'NTLM' -and
    $_.Properties[5].Value -ne 'ANONYMOUS LOGON' -and
    $_.Properties[5].Value -notlike '*$'
  } |
  ForEach-Object {
    [PSCustomObject]@{
      Account  = $_.Properties[5].Value
      SourceIP = $_.Properties[18].Value
      LogonId  = $_.Properties[7].Value
    }
  } |
  Group-Object Account, SourceIP |
  Select-Object @{n='Account';e={$_.Group[0].Account}},
                @{n='SourceIP';e={$_.Group[0].SourceIP}},
                @{n='DistinctLogonIds';e={($_.Group.LogonId | Sort-Object -Unique).Count}},
                @{n='Events';e={$_.Count}}
