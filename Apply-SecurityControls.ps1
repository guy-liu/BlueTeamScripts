
# Disable LLMNR
# Enable, set to 1, not configured, delete DNSClient
REG ADD  "HKLM\Software\policies\Microsoft\Windows NT\DNSClient"
REG ADD  "HKLM\Software\policies\Microsoft\Windows NT\DNSClient" /v "EnableMulticast" /t REG_DWORD /d "0" /f

# Disable NBT-NS for each interface
$regkey = "HKLM:SYSTEM\CurrentControlSet\services\NetBT\Parameters\Interfaces"
Get-ChildItem $regkey |foreach { Set-ItemProperty -Path "$regkey\$($_.pschildname)" -Name NetbiosOptions -Value 2 -Verbose}

# Disable IPv6 on all adapters
Get-NetAdapterBinding | Where-Object ComponentID -EQ 'ms_tcpip6' | Where-Object Enabled | ForEach-Object { Disable-NetAdapterBinding -Name $_.Name -ComponentID 'ms_tcpip6' }

# Enable SMB Signing
Set-SmbServerConfiguration -EnableSecuritySignature $true -RequireSecuritySignature $true -Confirm:$false
Set-SmbClientConfiguration -EnableSecuritySignature $true -RequireSecuritySignature $true -Confirm:$false

# Disable Null Session
REG ADD  "HKLM\SYSTEM\CurrentControlSet\Control\LSA" /v "RestrictAnonymous" /t REG_DWORD /d "1" /f

# Rename Administrator and Guest
Get-LocalUser | Where-Object {$_.SID.Value.StartsWith("S-1-5-")} | Where-Object {$_.SID.Value.EndsWith("500")} | ForEach-Object {Rename-LocalUser -Name $_.Name -NewName "BuiltinAccount1" }
Get-LocalUser | Where-Object {$_.SID.Value.StartsWith("S-1-5-")} | Where-Object {$_.SID.Value.EndsWith("501")} | ForEach-Object {Rename-LocalUser -Name $_.Name -NewName "BuiltinAccount2" }

# Disable Cached Logon Credentials
REG ADD  "HKLM\SOFTWARE\Microsoft\Windows NT\CurrentVersion\Winlogon" /v "CachedLogonsCount" /t REG_SZ /d "0" /f

# Disable Autorun
REG ADD  "HKLM\SOFTWARE\Microsoft\Windows\CurrentVersion\Policies\Explorer" /v "NoDriveTypeAutoRun" /t REG_DWORD /d "0xFF" /f

# Remove Vulnerable Codecs from StoreApps
Get-AppxPackage -Name Microsoft.HEIFImageExtension -AllUsers | Remove-AppxPackage -AllUsers
Get-AppxPackage -Name Microsoft.HEVCVideoExtension -AllUsers | Remove-AppxPackage -AllUsers

# If Qualys is installed, trigger scan

# Disable Modern Standby
reg add HKLM\System\CurrentControlSet\Control\Power /v PlatformAoAcOverride /t REG_DWORD /d 0