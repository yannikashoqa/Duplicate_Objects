#  Version 1.0
Function Duplicate_Object {
    param ( [Parameter(Mandatory = $true)]    $Object_URI,
        [Parameter(Mandatory = $true)]    $Object_ID,
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
    }  

    $ExistingObject_URI = $DS_HOST_URI + $Object_URI_Path + "/" + $Object_ID
    try {
        $CurrentObject = Invoke-RestMethod -Uri $ExistingObject_URI -Method Get -Headers $Headers -SkipCertificateCheck 
    }
    catch {
        Write-Host "[ERROR]	Failed to retreive $Object_URI_Path Object.	$_"
        exit    # Exit Script
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
        Switch ($Object_API_Path) {
            antimalwareconfigurations {
                $Object_API_Path = "antimalwareconfigurations"
            }
            directorylists { 
                $Object_API_Path = "directorylists"
            }
            filelists { 
                $Object_API_Path = "filelists"
            }
            processimage { 
                $Object_API_Path = "filelists"
            }
            fileextensionlists { 
                $Object_API_Path = "fileextensionlists"
            }  
        }
        $QUERY_PARAMS = $QUERY_PARAMS | ConvertTo-Json -Depth 4
        $SearchedObject = Invoke-RestMethod -Uri $SearchObject_URI -Method Post -Headers $Headers -Body $QUERY_PARAMS -SkipCertificateCheck 
        $SearchedObject_Name = $SearchedObject.$Object_API_Path.name

        if ($NewName -eq $SearchedObject_Name) {
            Return $SearchedObject.$Object_API_Path
        }
        Else {
            #Write-Host "[INFO] Object $SearchedObject_Name does not exist. Continue with script" #Not Needed
        }                    
    }
    catch {
        Write-Host "[ERROR] Failed to run Search. $_"
    }
    try {
        $CreateObjectURI = $DS_HOST_URI + $Object_URI_Path
        $ObjectItem_Duplicate = Invoke-RestMethod -Uri $CreateObjectURI -Method Post -Headers $Headers -Body $NewObject_JSON -SkipCertificateCheck 
        Write-Host "[INFO] Object Creation Successful: $CurrentObject.name"
        Return $ObjectItem_Duplicate
    }
    catch {
        Write-Host "[ERROR]	Failed to Create Item. $_"
    }
}

Function ProcessAMConfiguration{
    param ( [Parameter(Mandatory = $true)]    $AM_Configuration_Name)
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

    ################################################## DEV: Even if 0 and exit function, writing the policy will enable 
    ################################################## the Inhereted option on the Scan Configuration
    if ($ScanConfigurationID -eq 0){
        Return
    }

    $ScanConfigurations_URI = $DS_HOST_URI + "antimalwareconfigurations"
    $ScanConfiguration_URI = $ScanConfigurations_URI + "/" + $ScanConfigurationID 

    #Duplicate the Scan Configuration    
    try {
        $Duplicate_ScanConfig = Duplicate_Object -Object_URI $ScanConfigurations_URI -Object_ID $ScanConfigurationID -Object_API_Path "antimalwareconfigurations"
        $ScanConfiguration_URI = $ScanConfigurations_URI + "/" + $Duplicate_ScanConfig.ID
        $ScanConfiguration_Describe = Invoke-RestMethod -Uri $ScanConfiguration_URI -Method Get -Headers $Headers -SkipCertificateCheck 
    }
    catch {
        Write-Host "[ERROR] Failed to retreive the Scan Configuration"
    }      
    
    $ObjectsToModify = @("directorylists", "filelists", "fileextensionlists", "processimage")
    ForEach ($Object in $ObjectsToModify) {
        switch ($Object) {
            directorylists { $ExclusionListID = $ScanConfiguration_Describe.excludedDirectoryListID}
            filelists { $ExclusionListID = $ScanConfiguration_Describe.excludedFileListID}
            fileextensionlists { $ExclusionListID = $ScanConfiguration_Describe.excludedFileExtensionListID} 
            processimage { 
                $ScanConfigurationType = $ScanConfiguration_Describe.scanType
                If ($ScanConfigurationType -eq "real-time"){
                    $ExclusionListID = $ScanConfiguration_Describe.excludedProcessImageFileListID}
                }Else{
                    $ExclusionListID = $null    #Skip since on-demand scan configuration does not have Process Image exclusions
                }                
        }
        if ($null -eq $ExclusionListID){
            Continue
        }
        $ExclusionList_URI = $DS_HOST_URI + $Object
        $Duplicate_Exclusion = Duplicate_Object -Object_URI $ExclusionList_URI -Object_ID $ExclusionListID -Object_API_Path $Object
        
        #Update Duplicate Scan Configuration with Exclusion ID
        Switch ($Object) {
            directorylists { 
                $Body = @{
                    "excludedDirectoryListID" = $Duplicate_Exclusion.ID
                }                    
            }
            filelists { 
                $Body = @{
                    "excludedFileListID" = $Duplicate_Exclusion.ID
                }                    
            }
            processimage { 
                $Body = @{
                    "excludedProcessImageFileListID" = $Duplicate_Exclusion.ID
                }                    
            }
            fileextensionlists { 
                $Body = @{
                    "excludedFileExtensionListID" = $Duplicate_Exclusion.ID
                }                    
            }  
        }            
        
        $Body_Json = $Body | ConvertTo-Json -Depth 4
        $Modify_AM_ScanConfig_URI = $ScanConfigurations_URI + "/" + $Duplicate_ScanConfig.ID
        # Update Scan Configuration
        try {                
            $Modify_AM_ScanConfig = Invoke-RestMethod -Uri $Modify_AM_ScanConfig_URI -Method Post -Headers $Headers -Body $Body_Json -SkipCertificateCheck 
            $PolicySettingValue = $Modify_AM_ScanConfig.ID
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
            $PolicySettingUpdate = Invoke-RestMethod -Uri $PolicySettingToUpdate_URI -Method Post -Headers $Headers -Body $PolicySettingBody -SkipCertificateCheck     
        }
        catch {
            Write-Host "[ERROR]	Failed to update Policy Setting.	$_"
        }
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
        If ($Policy.name -eq "Base Policy") {
            Continue
        }
        If ($Policy.antiMalware.state -eq "off") {
            Continue
        }
        Write-Host "################################  Policy Section  ################################"
        Write-Host "Policy Name: " $Policy.name
        ProcessAMConfiguration -AM_Configuration_Name "realTimeScanConfiguration"
        ProcessAMConfiguration -AM_Configuration_Name "manualScanConfiguration"
        ProcessAMConfiguration -AM_Configuration_Name "scheduledScanConfiguration"
    } 
}
catch {
    Write-Host "[ERROR]	Failed to run main script.	$_"
}