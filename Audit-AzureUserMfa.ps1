# Based from Tony Redmond's code  https://office365itpros.com/2018/11/21/reporting-mfa-enabled-accounts/

# Check for MSOnline Module
if (Get-Module -ListAvailable -Name MSOnline) {
    Write-Host "[+] Checking for MSOnline Module - Installed"
} else {
    Write-Host "[-] Error. MSOnline module required. Install by running 'Install-Module MSOnline -Scope CurrentUser'"
}

# Check for connection to MSOL
$d= Get-MsolDomain -ErrorAction SilentlyContinue

if($?) {
	Write-Host "[+] Checking for MSOL Connection - Connected"
} else {
    Write-Host "[-] Checking for MSOL Connection - Not Connected. Running Connect-MsolService"
	Connect-MsolService
}

Write-Host "[+] Retrieving Azure AD 'Non-Guest' Users"

$Users = Get-MsolUser -All | Where-Object { $_.UserType -ne "Guest" }

$Report = [System.Collections.Generic.List[Object]]::new()

Write-Host "[+] Analysing MFA status for " $Users.Count " users" 

ForEach ($User in $Users) {

    $MFADefaultMethod = ($User.StrongAuthenticationMethods | Where-Object { $_.IsDefault -eq "True" }).MethodType
    $MFAPhoneNumber = $User.StrongAuthenticationUserDetails.PhoneNumber
    $PrimarySMTP = $User.ProxyAddresses | Where-Object { $_ -clike "SMTP*" } | ForEach-Object { $_ -replace "SMTP:", "" }
    $Aliases = $User.ProxyAddresses | Where-Object { $_ -clike "smtp*" } | ForEach-Object { $_ -replace "smtp:", "" }

    if ($User.StrongAuthenticationRequirements) {
        $MFAState = $User.StrongAuthenticationRequirements.State
    } else {
        $MFAState = 'Disabled'
    }

    if ($MFADefaultMethod) {
        switch ($MFADefaultMethod) {
            "OneWaySMS" { $MFADefaultMethod = "Text code authentication phone" }
            "TwoWayVoiceMobile" { $MFADefaultMethod = "Call authentication phone" }
            "TwoWayVoiceOffice" { $MFADefaultMethod = "Call office phone" }
            "PhoneAppOTP" { $MFADefaultMethod = "Authenticator app or hardware token" }
            "PhoneAppNotification" { $MFADefaultMethod = "Microsoft authenticator app" }
        }
    } else {
        $MFADefaultMethod = "Not enabled"
    }
  
    $ReportLine = [PSCustomObject] @{
        UserPrincipalName = $User.UserPrincipalName
        DisplayName       = $User.DisplayName
        MFAState          = $MFAState
        MFADefaultMethod  = $MFADefaultMethod
        MFAPhoneNumber    = $MFAPhoneNumber
        PrimarySMTP       = ($PrimarySMTP -join ',')
        Aliases           = ($Aliases -join ',')
		BlockCredential   = $User.BlockCredential
		LastDirSyncTime   = $User.LastDirSyncTime
		LastPasswordChange = $User.LastPasswordChangeTimestamp
    }
                 
    $Report.Add($ReportLine)
}

Write-Host "[+] Saving report in AzureUserMfaAudit.csv"

$Report | Sort-Object UserPrincipalName | Export-CSV -Encoding UTF8 -NoTypeInformation "AzureUserMfaAudit.csv"
