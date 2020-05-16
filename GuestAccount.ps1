
# Application (client) ID, tenant Name and secret
$clientId = "16caf9d1-e04f-41d0-9ddf-931a6f571de5"
$tenantName = "f429c771-2ff9-43d7-97e9-8f312cea4346"
$clientSecret = "y=f/gfYcrd?gujAShsRueC8Ndy2Ca[51"
#$clientSecret = "PYxQ@-XLr?A:RkNfZAnyJLIIhzVi4431"
$resource = "https://graph.microsoft.com/"

#Variable date-time for the last 1hr
$date = (Get-Date).AddHours(-2).ToString("yyyy-MM-ddTHH:MM:ssZ")

#Get Token
$ReqTokenBody = @{
    Grant_Type    = "client_credentials"
    Scope         = "https://graph.microsoft.com/.default"
    client_Id     = $clientID
    Client_Secret = $clientSecret
} 
$TokenResponse = Invoke-RestMethod -Uri "https://login.microsoftonline.com/$TenantName/oauth2/v2.0/token" -Method POST -Body $ReqTokenBody

#Get all succesfully created users for the last 1hr
$AddUserGraph = "https://graph.microsoft.com/beta/auditLogs/directoryAudits?`$filter=activityDateTime ge $date and activityDisplayName eq 'Add user' and result eq 'success'"
$AddUserGraphData = Invoke-RestMethod -Headers @{Authorization = "Bearer $($Tokenresponse.access_token)" } -Uri $AddUserGraph -Method Get

#Get all succesfully deleted users for the last 1hr
$DeleteUserGraph = "https://graph.microsoft.com/beta/auditLogs/directoryAudits?`$filter=activityDateTime ge $date and activityDisplayName eq 'Delete user' and result eq 'success'"
$DeleteUserGraphData = Invoke-RestMethod -Headers @{Authorization = "Bearer $($Tokenresponse.access_token)" } -Uri $DeleteUserGraph -Method Get


#Get all succesfully Restored users for the last 1hr
$RestoreUserGraph = "https://graph.microsoft.com/v1.0/auditLogs/directoryAudits?`$filter=activityDateTime ge $date and category eq 'UserManagement' and operationType eq 'Restore' and result eq 'success'"
$RestoreUserGraphData = Invoke-RestMethod -Headers @{Authorization = "Bearer $($Tokenresponse.access_token)" } -Uri $RestoreUserGraph -Method Get
Function Get-Restore {
    $RestoredUserResults = @()
    for ($r = 0; $r -lt $RestoreUserGraphData.value.count; $r++) {
        $UPN = $RestoreUserGraphData.value[$r].targetResources.userPrincipalName
        if ($UPN -notmatch "#EXT#@ggicocloudoutlook.onmicrosoft.com") {
            try {
                $RestoreUser = "https://graph.microsoft.com/BETA/users/$UPN"
                $RestoreUserData = Invoke-RestMethod -Headers @{Authorization = "Bearer $($Tokenresponse.access_token)" } -Uri $RestoreUser -Method Get
                $RestoredUserResults += [PSCustomObject]@{
                    UserPrincipalName = $RestoreUserData.UserPrincipalName
                    GivenName         = $RestoreUserData.givenName
                    Surname           = $RestoreUserData.surname
                    EmployeeID        = $null
                    Result            = $RestoreUserGraphData.value[$r].OperationType
                }
            }
            catch { Write-Host "$UPN does not exist $PSItem" }
        }
        #Clear-Variable RestoreUserData
        #Clear-Variable RestoreUserGraphData
    }
    $RestoredUserResults
}

Function Get-Creation {
    [array]$AddUserResults = @()
    for ($i = 0; $i -lt $AddUserGraphData.value.count; $i++) {
        $UPN = $AddUserGraphData.value[$i].targetResources.userPrincipalName
        if ($UPN -notmatch "#EXT#@ggicocloudoutlook.onmicrosoft.com") {
            try {
                $User = "https://graph.microsoft.com/BETA/users/$UPN"
                $UserData = Invoke-RestMethod -Headers @{Authorization = "Bearer $($Tokenresponse.access_token)" } -Uri $User -Method Get
                $AddUserResults += [PSCustomObject]@{
                    UserPrincipalName = $UserData.UserPrincipalName
                    GivenName         = $UserData.givenName
                    Surname           = $UserData.surname
                    EmployeeID        = $UserData.employeeId
                    Result            = $AddUserGraphData.value[$i].OperationType
                }
            }
            catch {
                Write-Host "$UPN does not existffff $PSItem" 
  
            }
    
        }
        #Clear-Variable UserData
        #Clear-Variable AddUserGraphData
    }
    $AddUserResults

}

Function Get-DelUsers {
    [array]$DeleteUserResults = @()
    #$HashUsers = Get-Creation
    #$DeleteUserResults += $HashUsers
    for ($d = 0; $d -lt $DeleteUserGraphData.value.count; $d++) {
        $UPNDEL = ($DeleteUserGraphData.value[$d].targetResources.userPrincipalName).Substring(32)
        if ($UPNDEL -notmatch "#EXT#@ggicocloudoutlook.onmicrosoft.com") {
            try {
                $DelUser = "https://graph.microsoft.com/BETA/users/$UPNDEL"
                $DelUserData = Invoke-RestMethod -Headers @{Authorization = "Bearer $($Tokenresponse.access_token)" } -Uri $DelUser -Method Get -ErrorAction SilentlyContinue
                Write-Host "$UPNDEL already exist"
            }
            catch {
                $DeleteUserResults += [PSCustomObject]@{
                    UserPrincipalName = $UPNDEL
                    GivenName         = $null
                    Surname           = $null
                    EmployeeID        = $null
                    Result            = $DeleteUserGraphData.value[$d].OperationType
                }
            }
        }
        else { write-host "$UPNDEL now world" }

    }
    $DeleteUserResults
}

Function Get-AllUsers {
    $AddUser = @()
    $AddUser += Get-Creation 
    $AddUser += Get-Restore 
    $AddUser += Get-DelUsers 
    $AddUser
}
$AllUserDataResults = Get-AllUsers | Sort-Object -Property UserPrincipalName -Unique
##########################OUTFROM-SYNCENGINE########################################
#Function Push-ROSPOC {
    [array]$Addbody = @()
    [array]$Delbody = @()
    $RedirectURI = "https://myapp.microsoft.com"
    $body = @()
    $Token = Invoke-RestMethod -Uri "https://login.microsoftonline.com/81b2b335-4298-4b51-837e-e71a9da239b0/oauth2/v2.0/token" -Method POST -Body $ReqTokenBody
    #$TenantID = Get-AutomationVariable -Name 'Guest_ROSPOC_TenantID'
    #Connect-azureAD -TenantId $TenantID -ApplicationId $clientId -CertificateThumbprint $Cred
    foreach ($output in $AllUserDataResults) {
        switch ($output.Result) {
 { $output.Result -eq "Add" } {   
                [string]$UPN = $output.UserPrincipalName
                [string]$GivenName = $output.GivenName
                [string]$Surname = $output.Surname
                [string]$EmployeeID = $output.EmployeeID
                $DisplayName = "$GivenName $Surname"
                [string]$email = [System.Web.HttpUtility]::UrlEncode(($UPN -replace "@", "_") + "#EXT#@rospoc.onmicrosoft.com")
                Try {
                    $GraphAddUser = "https://graph.microsoft.com/BETA/users/$email"
                    Invoke-RestMethod -Headers @{Authorization = "Bearer $($Token.access_token)" } -Uri $GraphAddUser -Method Get -ErrorAction SilentlyContinue
                    write-output "User with Display Name $DisplayName and UserPrincipalName $UPN exist."
                }
                catch {
                    $body = @{
                        "invitedUserEmailAddress" = $UPN
                        "inviteRedirectUrl"       = $RedirectURI
                        "invitedUserDisplayName"  = $DisplayName
                    } | ConvertTo-Json
                    $AddUserGraph = "https://graph.microsoft.com/v1.0/invitations"
                    Invoke-RestMethod -Headers @{Authorization = "Bearer $($Token.access_token)" } -Uri $AddUserGraph -Method POST -Body $body
                    $Addbody += [PSCustomObject]@{
                        "Display Name"     = $DisplayName
                        UserPrincipalName  = $UPN
                        "Removed UserName" = $null
                }

            }   
            }
 { $output.Result -eq "Restore" } {  
                [string]$UPN = $output.UserPrincipalName
            
                Try {
                $GraphCheckUser = "https://graph.microsoft.com/BETA/directory/deletedItems/microsoft.graph.user?`$filter=startswith(mail, '$UPN')"
                $DataGraphcheckUser = Invoke-RestMethod -Headers @{Authorization = "Bearer $($Token.access_token)" } -Uri $GraphCheckUser -Method Get -ErrorAction SilentlyContinue
                $ObjectID = $DataGraphCheckUser.value.id
                $GraphRestoreUser = "https://graph.microsoft.com/v1.0/directory/deletedItems/$ObjectID/restore"
                $DataGraphRestoreUser = Invoke-RestMethod -Headers @{Authorization = "Bearer $($Token.access_token)"} -ContentType "application/json" -Uri $GraphRestoreUser -Method POST -ErrorAction SilentlyContinue
                write-output "User with Display Name $DisplayName and UserPrincipalName $UPN has been restored."
            }
            catch {
                $body = @{
                    "invitedUserEmailAddress" = $UPN
                    "inviteRedirectUrl"       = $RedirectURI
                    "invitedUserDisplayName"  = $DisplayName
                } | ConvertTo-Json
                $AddUserGraph = "https://graph.microsoft.com/v1.0/invitations"
                Invoke-RestMethod -Headers @{Authorization = "Bearer $($Token.access_token)" } -Uri $AddUserGraph -Method POST -Body $body
                $Addbody += [PSCustomObject]@{
                    "Display Name"     = $DisplayName
                    UserPrincipalName  = $UPN
                    "Removed UserName" = $null
            }
        }   
    }
 { $output.Result -eq "Delete" } {  
                [string]$UPN = $output.UserPrincipalName
                [string]$email = [System.Web.HttpUtility]::UrlEncode(($UPN -replace "@", "_") + "#EXT#@rospoc.onmicrosoft.com")
                Try {
                    $UserDel = "https://graph.microsoft.com/BETA/users/$email"
                    Invoke-RestMethod -Headers @{Authorization = "Bearer $($Token.access_token)" } -Uri $UserDel -Method Delete -ErrorAction SilentlyContinue
                    $Delbody += [PSCustomObject]@{  
                        "Display Name"     = $null
                        UserPrincipalName  = $null
                        "Removed UserName" = $UPN
                    }
                }
                catch {
                    write-output " $UPN User Does not Exist or has been already deleted"
                }  
            }
        
        }
}
<# $body += $Addbody
$body += $Delbody
write-output $body
$style = "<style>BODY{font-family: Arial; font-size: 10pt;}"
$style = $style + "TABLE{border: 1px solid black; border-collapse: collapse;}"
$style = $style + "TH{border: 1px solid black; background: #dddddd; padding: 5px; }"
$style = $style + "TD{border: 1px solid black; padding: 5px; }"
$style = $style + "</style>"
$Header = Out-String -InputObject ($body | ConvertTo-Html -head $style -Body "<font color=`"Black`"><h4><left>Guest Users Report</left></h4></font>")
$mailParams = @{
    SmtpServer                 = 'smtp.office365.com'
    Port                       = '587' # or '25' if not using TLS
    UseSSL                     = $true ## or not if using non-TLS
    Credential                 = $Credentials
    From                       = 'gobinath@rospoc.onmicrosoft.com'
    To                         = 'v-gomage@microsoft.com'
    Subject                    = "Guest Account Created"
    DeliveryNotificationOption = 'OnFailure', 'OnSuccess'
}
if ($body -ne $null) { Send-MailMessage @mailParams -Body $Header -BodyAsHtml } #>
#}
#Push-ROSPOC

