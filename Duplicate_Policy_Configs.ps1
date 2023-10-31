#  Version 1.7
Function Duplicate_Object {
    param ( [Parameter(Mandatory = $true)]    $Object_ID,
        [Parameter(Mandatory = $true)]    $Object_API_Path )

    Switch ($Object_API_Path) {
        antimalwareconfigurations {
            $Object_URI_Path = "antimalwareconfigurations"
        }
        directorylists { 
            $Object_URI_Path = "directorylists"
        }
        filelists { 
            $Object_URI_Path = "filelists"
        }
        processimage { 
            $Object_URI_Path = "filelists"
        }
        fileextensionlists { 
            $Object_URI_Path = "fileextensionlists"
        } 
        firewallrules {
            $Object_URI_Path = "firewallrules"
        }
        iplists {
            $Object_URI_Path = "iplists"
        }
        portlists {
            $Object_URI_Path = "portlists"
        }
    }  

    $ExistingObject_URI = $DS_HOST_URI + $Object_URI_Path + "/" + $Object_ID
    try {
        $CurrentObject = Invoke-RestMethod -Uri $ExistingObject_URI -Method Get -Headers $Headers -SkipCertificateCheck 
    }
    catch {
        Write-Host "[ERROR]	Failed to retreive $Object_URI_Path Object.	$_"
        exit
    }    

    $ExistingName = $CurrentObject.name
    if ($ExistingName.StartsWith($PreFix)) {
        Return $CurrentObject  
    }
                
    $NewName = $PreFix + $ExistingName
    $CurrentObject.name = $NewName
    $NewObject_NoID = $CurrentObject | Select-Object -Property * -ExcludeProperty "ID"
    $NewObject_JSON = $NewObject_NoID | ConvertTo-Json -Depth 4

    #Search for new Object name before creating  
    try {
        $SearchObject_URI = $DS_HOST_URI + $Object_URI_Path + "/search"
        $QUERY_PARAMS = @{
            searchCriteria = @{
                fieldName   = "name"
                stringTest  = "equal"
                stringValue = $NewName
            }
        }
        $QUERY_PARAMS = $QUERY_PARAMS | ConvertTo-Json -Depth 4
        $SearchedObject = Invoke-RestMethod -Uri $SearchObject_URI -Method Post -Headers $Headers -Body $QUERY_PARAMS -SkipCertificateCheck 
        $SearchedObject_Name = $SearchedObject.$Object_URI_Path.name
        if ($NewName -eq $SearchedObject_Name) {
            Return $SearchedObject.$Object_URI_Path
        }                   
    }
    catch {
        Write-Host "[ERROR] Failed to run Search. $_"
    }

    try {
        $CreateObjectURI = $DS_HOST_URI + $Object_URI_Path
        $ObjectItem_Duplicate = Invoke-RestMethod -Uri $CreateObjectURI -Method Post -Headers $Headers -Body $NewObject_JSON -SkipCertificateCheck 
        Write-Host "[INFO] Object Creation Successful: " $CurrentObject.name
        Return $ObjectItem_Duplicate
    }
    catch {
        Write-Host "[ERROR]	Failed to Create Item. $_"
    }
}

Function ProcessAMConfiguration{
    param ( [Parameter(Mandatory = $true)]    $AM_Configuration_Name)
    Write-Host ""
    Write-Host "====================================================="
    Write-Host "[INFO] Processing $AM_Configuration_Name"
    Switch ($AM_Configuration_Name) {
        realTimeScanConfiguration { 
            $ScanConfigurationID = $Policy.antiMalware.realTimeScanConfigurationID
            $ScanConfigurationID_Text = "realTimeScanConfigurationID"
        }
        manualScanConfiguration { 
            $ScanConfigurationID = $Policy.antiMalware.manualScanConfigurationID
            $ScanConfigurationID_Text = "manualScanConfigurationID"
        }
        scheduledScanConfiguration { 
            $ScanConfigurationID =$Policy.antiMalware.scheduledScanConfigurationID
            $ScanConfigurationID_Text = "scheduledScanConfigurationID"
        }
    }

    $ScanConfigurations_URI = $DS_HOST_URI + "antimalwareconfigurations"
    try {
        $Duplicate_ScanConfig = Duplicate_Object -Object_ID $ScanConfigurationID -Object_API_Path "antimalwareconfigurations"
        $Duplicate_ScanConfiguration_URI = $ScanConfigurations_URI + "/" + $Duplicate_ScanConfig.ID
        $ScanConfiguration_Describe = Invoke-RestMethod -Uri $Duplicate_ScanConfiguration_URI -Method Get -Headers $Headers -SkipCertificateCheck 
    }
    catch {
        Write-Host "[ERROR] Failed to retreive the Scan Configuration"
    }

    $ObjectsToModify = @("directorylists", "filelists", "fileextensionlists", "processimage")
    ForEach ($Object in $ObjectsToModify) {
        $Skip = $false
        switch ($Object) {
            directorylists { 
                if (($ScanConfiguration_Describe | ConvertTo-Json).Contains("excludedDirectoryListID")){
                    $ExclusionListID = $ScanConfiguration_Describe.excludedDirectoryListID
                    $Duplicate_Exclusion = Duplicate_Object -Object_ID $ExclusionListID -Object_API_Path $Object
                    $Body = @{
                        "excludedDirectoryListID" = $Duplicate_Exclusion.ID
                    } 
                }Else{
                    Write-Host "[INFO] excludedDirectoryListID Does not Exist"
                    $Skip = $True
                }
            }
            filelists { 
                if (($ScanConfiguration_Describe | ConvertTo-Json).Contains("excludedFileListID")){
                    $ExclusionListID = $ScanConfiguration_Describe.excludedFileListID
                    $Duplicate_Exclusion = Duplicate_Object -Object_ID $ExclusionListID -Object_API_Path $Object
                    $Body = @{
                        "excludedFileListID" = $Duplicate_Exclusion.ID
                    }  
                }Else{
                    Write-Host "[INFO] excludedFileListID Does not Exist"
                    $Skip = $True
                }              
            }
            fileextensionlists { 
                if (($ScanConfiguration_Describe | ConvertTo-Json).Contains("excludedFileExtensionListID")){
                    $ExclusionListID = $ScanConfiguration_Describe.excludedFileExtensionListID
                    $Duplicate_Exclusion = Duplicate_Object -Object_ID $ExclusionListID -Object_API_Path $Object
                    $Body = @{
                        "excludedFileExtensionListID" = $Duplicate_Exclusion.ID
                    } 
                }Else{
                    Write-Host "[INFO] excludedFileExtensionListID Does not Exist"
                    $Skip = $True
                }              
            } 
            processimage { 
                $ScanConfigurationType = $ScanConfiguration_Describe.scanType
                if (($ScanConfiguration_Describe | ConvertTo-Json).Contains("excludedProcessImageFileListID")){
                    If ($ScanConfigurationType -eq "real-time"){                    
                        $ExclusionListID = $ScanConfiguration_Describe.excludedProcessImageFileListID
                        $Duplicate_Exclusion = Duplicate_Object -Object_ID $ExclusionListID -Object_API_Path "filelists"
                        $Body = @{
                            "excludedProcessImageFileListID" = $Duplicate_Exclusion.ID
                        } 
                    }
                }else {
                    Write-Host "[INFO] excludedProcessImageFileListID Does not Exist"
                    $Skip = $True
                }                
            }            
        }

        # For Realtime Scan Configuration check if all Exclusions are disabled
        If ($ScanConfiguration_Describe.scanType -eq "real-time" -and
            -not (($ScanConfiguration_Describe | ConvertTo-Json).Contains("excludedDirectoryListID")) -and`
            -not (($ScanConfiguration_Describe | ConvertTo-Json).Contains("excludedFileListID")) -and`
            -not (($ScanConfiguration_Describe | ConvertTo-Json).Contains("excludedFileExtensionListID")) -and`
            -not (($ScanConfiguration_Describe | ConvertTo-Json).Contains("excludedProcessImageFileListID")) ){        
                #Blank Body
                $Body = @{
                } 
                $AllDisabled = $true
            }

        # For OnDemand Scan Configuration there is not Process Image Exclusions
        If ($ScanConfiguration_Describe.scanType -eq "on-demand" -and
            -not (($ScanConfiguration_Describe | ConvertTo-Json).Contains("excludedDirectoryListID")) -and`
            -not (($ScanConfiguration_Describe | ConvertTo-Json).Contains("excludedFileListID")) -and`
            -not (($ScanConfiguration_Describe | ConvertTo-Json).Contains("excludedFileExtensionListID"))){        
                #Blank Body
                $Body = @{
                } 
                $AllDisabled = $true
            }

        If ($Skip -and !$AllDisabled){
            Write-Host "[INFO] Skipping Exclusion List ($Object) since it is not enabled."
        }else {
            $Body_Json = $Body | ConvertTo-Json -Depth 4
            # Update Scan Configuration
            try {                
                $Updated_AM_ScanConfig = Invoke-RestMethod -Uri $Duplicate_ScanConfiguration_URI -Method Post -Headers $Headers -Body $Body_Json -SkipCertificateCheck 
                $PolicySettingValue = $Updated_AM_ScanConfig.ID
                $PolicySettingPayload = @{
                    "antiMalware" = @{
                        $ScanConfigurationID_Text = $PolicySettingValue
                    }
                }
                $PolicySettingBody = $PolicySettingPayload | ConvertTo-Json -Depth 4
            }
            catch {
                Write-Host "[ERROR]	Failed to update Security Config Setting.	$_"
            }
            # Update the Policy
            try {
                $PolicySettingToUpdate_URI = $Policies_URI + "/" + $Policy.ID
                $UpdatedPolicy = Invoke-RestMethod -Uri $PolicySettingToUpdate_URI -Method Post -Headers $Headers -Body $PolicySettingBody -SkipCertificateCheck 
            }
            catch {
                Write-Host "[ERROR]	Failed to update Policy Setting.	$_"
            }
        }
    }
}

Function ProcessFWConfiguration{
    param ( [Parameter(Mandatory = $true)]    $PolicyID)
    Write-Host ""
    Write-Host "====================================================="
    Write-Host "[INFO] Processing Policy ID: $PolicyID"
    $DescribePolicy_URI = $DS_HOST_URI + "policies/" + $PolicyID
    try {
        $DescribePolicy = Invoke-RestMethod -Uri $DescribePolicy_URI -Method Get -Headers $Headers -SkipCertificateCheck 
    }
    catch {
        Write-Host "[ERROR]	Failed to Describe Policy Setting.	$_"
    }
    $FirewallRuleIDs = $DescribePolicy.firewall.ruleIDs
    $Index = 0
    foreach ($FirewallRuleID in $FirewallRuleIDs){
        $DuplicateFireWallRule = Duplicate_Object -Object_ID $FirewallRuleID -Object_API_Path "firewallrules"
        $DuplicateFireWallRule_URI = $DS_HOST_URI + "firewallrules/" + $DuplicateFireWallRule.ID
        try {
            $Describe_DuplicateFireWallRule = Invoke-RestMethod -Uri $DuplicateFireWallRule_URI -Method Get -Headers $Headers -SkipCertificateCheck
        }
        catch {
            Write-Host "[ERROR]	Failed to Describe Duplicate FW Rule.	$_"
        }        
        If ($Describe_DuplicateFireWallRule.sourceIPType -eq "ip-list"){
            $SourceIPListID = $Describe_DuplicateFireWallRule.sourceIPListID
            Write-Host "[INFO] Duplicating IP List ID: $SourceIPListID" 
            $DuplicateSourceIPList = Duplicate_Object -Object_ID $SourceIPListID -Object_API_Path "iplists"
        }
        If ($Describe_DuplicateFireWallRule.destinationIPType -eq "ip-list"){
            $DestinationIPListID = $Describe_DuplicateFireWallRule.destinationIPListID
            Write-Host "[INFO] Duplicating IP List ID: $DestinationIPListID" 
            $DuplicateDestinationIPList = Duplicate_Object -Object_ID $DestinationIPListID -Object_API_Path "iplists"
        }
        If ($Describe_DuplicateFireWallRule.sourcePortType -eq "port-list"){
            $SourcePortListID = $Describe_DuplicateFireWallRule.sourcePortListID
            Write-Host "[INFO] Duplicating Port List ID: $SourcePortListID" 
            $DuplicateSourcePortList = Duplicate_Object -Object_ID $SourcePortListID -Object_API_Path "portlists"
        }
        If ($Describe_DuplicateFireWallRule.destinationPortType -eq "port-list"){
            $DestinationPortListID = $Describe_DuplicateFireWallRule.destinationPortListID
            Write-Host "[INFO] Duplicating Port List ID: $DestinationPortListID" 
            $DuplicateDestinationPortList = Duplicate_Object -Object_ID $DestinationPortListID -Object_API_Path "portlists"
        }
        $Body = @{
            "sourceIPListID" = $DuplicateSourceIPList.ID
            "destinationIPListID" = $DuplicateDestinationIPList.ID
            "sourcePortListID" = $DuplicateSourcePortList.ID
            "destinationPortListID" = $DuplicateDestinationPortList.ID
        }
        $Body_JSON = $Body | ConvertTo-Json
        try {
            $Update_DuplicateFireWallRule = Invoke-RestMethod -Uri $DuplicateFireWallRule_URI -Method Post -Body $Body_JSON -Headers $Headers -SkipCertificateCheck
            $FirewallRuleIDs[$Index] = $Update_DuplicateFireWallRule.ID
        }
        catch {
            Write-Host "[ERROR]	Failed to Update Duplicate FW Rule.	$_"
        }
        $Index++
    }

    $PolicySettingValue = $FirewallRuleIDs
    $PolicySettingPayload = @{
        "firewall" = @{
            "ruleIDs" = $PolicySettingValue 
        }
    }
    $PolicySettingBody = $PolicySettingPayload | ConvertTo-Json -Depth 4
    # Update the Policy
    try {
        $PolicySettingToUpdate_URI = $Policies_URI + "/" + $Policy.ID
        $UpdatedPolicy = Invoke-RestMethod -Uri $PolicySettingToUpdate_URI -Method Post -Headers $Headers -Body $PolicySettingBody -SkipCertificateCheck 
    }
    catch {
        Write-Host "[ERROR]	Failed to update Policy Setting.	$_"
    } 
}

Clear-Host
Write-Host "################################  Start of Script  ################################"
[Net.ServicePointManager]::SecurityProtocol = [Net.SecurityProtocolType]::Tls12
[System.Net.ServicePointManager]::ServerCertificateValidationCallback = { $true }
$ErrorActionPreference = 'Stop'

$Config = (Get-Content "$PSScriptRoot\DS-Config.json" -Raw) | ConvertFrom-Json
$Manager = $Config.MANAGER
$APIKEY = $Config.APIKEY
$PORT = $Config.PORT
$PreFix = $Config.PREFIX

$headers = New-Object "System.Collections.Generic.Dictionary[[String],[String]]"
$headers.Add("api-secret-key", $APIKEY)
$headers.Add("api-version", 'v1')
$headers.Add("Content-Type", 'application/json')

$DS_HOST_URI = "https://" + $Manager + ":" + $PORT + "/api/"
$PoliciesAPIPath = "policies"
$Policies_URI = $DS_HOST_URI + $PoliciesAPIPath
try {
    try {
        $Policy_REST = Invoke-RestMethod -Uri $Policies_URI -Method Get -Headers $Headers -SkipCertificateCheck  
    }
    catch {
        Write-Host "[ERROR] Failed to retreive the Policies"
    }
    $PolicyList = $Policy_REST.$PoliciesAPIPath
    ForEach ($Policy in $PolicyList) {
        Write-Host "################################  Policy Section  ################################"
        $PolicyName = $Policy.name
        $PolicyID = $Policy.ID
        Write-Host "Policy Name: " $PolicyName
        ProcessAMConfiguration -AM_Configuration_Name "realTimeScanConfiguration"
        ProcessAMConfiguration -AM_Configuration_Name "manualScanConfiguration"
        ProcessAMConfiguration -AM_Configuration_Name "scheduledScanConfiguration"
        ProcessFWConfiguration -PolicyID $PolicyID
    } 
}
catch {
    Write-Host "[ERROR]	Failed to run main script.	$_"
}