# GOOGLE CLOUD PROJECT SERVICE ACCOUNT
$serviceaccount= 'YourGCPServiceAccount@xxx-xxx-xxx.xxx.xxxx.com'

# GOOGLE CLOUD TARGET REGIONS
[array]$regions = @(
    "northamerica-northeast1",
    "northamerica-northeast2",
    "southamerica-east1",
    "southamerica-west1",
    "us-central1",
    "us-east1",
    "us-east4",
    "us-east5",
    "us-south1",
    "us-west1",
    "us-west2",
    "us-west3",
    "us-west4"
)

# AUTH OBJECT FOR CSM
$global:AuthObjectCsm = $null

# AUTH OBJECT FOR GCP
$global:AuthObjectGcP = $null

function connect-csmapi {

    [CmdletBinding()]
    param (
    )
    begin {
    }
    process {
        <#
            PowerShell SecretManagement
        #>
        try {
            $Credential = Get-Secret -Name 'CSM' -ErrorAction Stop
        }
        catch {
            $Credential = Get-Credential -Message "[Cloud Snapshot Manager]: Enter your credentials"
            Set-Secret -Name 'CSM' -Secret $Credential -Vault LocalStore -Metadata @{Information="Cloud Snapshot Manager"}
        } finally {
            $body = @(
                "grant_type=client_credentials",
                "client_id=$($Credential.username)",
                "client_secret=$(ConvertFrom-SecureString -SecureString $Credential.password -AsPlainText)"
            )
        
            $auth = Invoke-RestMethod `
                -Uri "https://ssgosge.emc.com/external/auth/oauth/v2/token" `
                -Method POST `
                -ContentType 'application/x-www-form-urlencoded' `
                -Body ($body -join '&') `
                -SkipCertificateCheck

            $Object = @{
                server = "https://ssgosge.emc.com/csm/v1"
                token= @{
                    authorization="Bearer $($auth.access_token)"
                    accept='application/json'
                } #END TOKEN
            } #END AUTHOBJ

            $global:AuthObjectCsm = $Object
            $global:AuthObjectCsm | Format-List
        }
    } #END PROCESS
} #END FUNCTION

function get-csmcloudaccounts {

    [CmdletBinding()]
    param (
    )
    begin {}
    process {
        
        $Results = @()

        $Endpoint = "cloud_accounts"
        $Query =  Invoke-RestMethod -Uri "$($AuthObjectCsm.server)/$($Endpoint)" `
        -Method GET `
        -ContentType 'application/json' `
        -Headers ($global:AuthObjectCsm.token) `
        -SkipCertificateCheck
        $Results = $Query
        
        return $Results

    } # END PROCESS
}

function new-csmcloudaccount {

    [CmdletBinding()]
    param (
        [Parameter( Mandatory=$true)]
        [object]$Body
    )
    begin {}
    process {
        
        $Results = @()

        $Endpoint = "cloud_accounts"
        $Action =  Invoke-RestMethod -Uri "$($AuthObjectCsm.server)/$($Endpoint)" `
        -Method POST `
        -ContentType 'application/json' `
        -Headers ($AuthObjectCsm.token) `
        -Body ($Body | ConvertTo-Json -Depth 10) `
        -SkipCertificateCheck
        $Results = $Action
        
        return $Results

    } # END PROCESS
}

function get-gcptoken {
    [CmdletBinding()]
    param (
    )
    begin {}
    process {

        $Token = gcloud auth print-access-token
        $Object = @{
            token= @{
                authorization="Bearer $($Token)"
                accept='application/json'
            } #END TOKEN
        } #END AUTHOBJ

        $global:AuthObjectGcp = $Object
        $global:AuthObjectGcp | Format-List
    }
}

function get-gcpprojects {
    [CmdletBinding()]
    param (
        
    )
    begin {}
    process {
      
        $Results = @()

        $Query =  Invoke-RestMethod `
        -Uri "https://cloudresourcemanager.googleapis.com/v3/projects:search?query=state%3DACTIVE" `
        -Method GET `
        -ContentType 'application/json' `
        -Headers ($AuthObjectGcp.token) `
        -SkipCertificateCheck
        $Results = $Query.projects
        
        return $Results
    }
}

# BEGIN THE WORKFLOW
$cloudaccounts = @()

# GET THE ACCESS TOKEN
get-gcptoken

# GET THE GCP PROJECTS
$gcp = get-gcpprojects
Write-Host "[GCP]: Projects" -ForegroundColor Yellow
$gcp | Format-List

# CONNECT TO THE CSM API
connect-csmapi

# QUERY FOR THE CLOUD ACCOUNTS
$csm = get-csmcloudaccounts | `
where-object {$_.cloud_provider -eq 'gcp'}

Write-Host "[CSM]: Cloud Accounts" -ForegroundColor Yellow
$csm | Format-List

foreach($project in $gcp) {
    $match = $csm | Where-Object {$_.project_id -eq $project.projectId}
    if(!$match) {
        # BUIILD THE CSM REQUEST BODY
        $object = [ordered]@{
            id=""
            cloud_provider = "gcp"
            display_name = "$($project.projectId)"
            description = "$($project.displayName)"
            project_id = "$($project.projectId)"
            type = "regular"
            regions = $regions
            client_email = "$($serviceaccount)"
            private_key = Get-Secret -Name $serviceaccount -AsPlainText
        } # END CSM REQUEST BODY
        $cloudaccounts += (New-Object -TypeName psobject -Property $object)
    }
}

Write-Host "[NO MATCHES]: Create a CSM Cloud Account" -ForegroundColor Yellow
foreach($account in $cloudaccounts) {
    try {
        # $account|convertto-json -Depth 10
        new-csmcloudaccount -Body $account
    }
    catch {
        $object = $_.ErrorDetails.Message | ConvertFrom-Json
        Write-Host "[ERROR]: During operation =>`n$($object.errors|convertto-json -Depth 10)" -ForegroundColor red
        $account|convertto-json -Depth 10
    }
}