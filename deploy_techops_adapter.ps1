param(
    [string]$ResourceGroup = "SMG",
    [string]$ContainerAppName = "techops-adapter",
    [string]$AcrName = "ca9238be9980acr",
    [string]$ImageName = "techops-adapter",
    [string]$ImageTag = "latest",
    [string]$KeyVaultName = "smg-mcp-kv",
    [string]$SmgMcpUrl = "https://smg-mcp.orangefield-2f3fdb87.westus3.azurecontainerapps.io/mcp",
    [string]$AutotaskBaseUrl = "",
    [string]$AutotaskUsernameSecretName = "autotask-username",
    [string]$AutotaskSecretSecretName = "autotask-secret",
    [string]$AutotaskIntegrationCodeSecretName = "autotask-integration-code",
    [int]$RefreshWindowHours = 72,
    [string]$OfficeIpCidr = "99.65.194.241/32",
    [string]$EnforceIpAllowlist = "true"
)

$ErrorActionPreference = "Stop"

Write-Host "Building container image in ACR..."
$scriptDir = Split-Path -Parent $MyInvocation.MyCommand.Path
Push-Location $scriptDir
az acr build --registry $AcrName --image "$ImageName`:$ImageTag" . --no-logs
Pop-Location

$imageRef = "$AcrName.azurecr.io/$ImageName`:$ImageTag"
Write-Host "Image built: $imageRef"

Write-Host "Resolving Container Apps environment from smg-mcp..."
$envId = az containerapp show -n smg-mcp -g $ResourceGroup --query "properties.managedEnvironmentId" -o tsv
if (-not $envId) { throw "Could not resolve managed environment ID from smg-mcp." }

Write-Host "Fetching SMG API key from Key Vault..."
$apiKey = az keyvault secret show --vault-name $KeyVaultName --name smg-api-key --query value -o tsv
if (-not $apiKey) { throw "smg-api-key not found in Key Vault $KeyVaultName." }

$hasDirectAutotask = -not [string]::IsNullOrWhiteSpace($AutotaskBaseUrl)
$autotaskUsername = ""
$autotaskSecret = ""
$autotaskIntegrationCode = ""
if ($hasDirectAutotask) {
    Write-Host "Fetching direct Autotask credentials from Key Vault..."
    $autotaskUsername = az keyvault secret show --vault-name $KeyVaultName --name $AutotaskUsernameSecretName --query value -o tsv
    $autotaskSecret = az keyvault secret show --vault-name $KeyVaultName --name $AutotaskSecretSecretName --query value -o tsv
    $autotaskIntegrationCode = az keyvault secret show --vault-name $KeyVaultName --name $AutotaskIntegrationCodeSecretName --query value -o tsv
    if (-not $autotaskUsername) { throw "Autotask username secret '$AutotaskUsernameSecretName' not found in Key Vault $KeyVaultName." }
    if (-not $autotaskSecret) { throw "Autotask secret '$AutotaskSecretSecretName' not found in Key Vault $KeyVaultName." }
    if (-not $autotaskIntegrationCode) { throw "Autotask integration code secret '$AutotaskIntegrationCodeSecretName' not found in Key Vault $KeyVaultName." }
}

$envVars = @(
    "SMG_MCP_URL=$SmgMcpUrl",
    "SMG_API_KEY=secretref:smg-api-key",
    "REFRESH_WINDOW_HOURS=$RefreshWindowHours",
    "TECHOPS_ALLOWED_IPS=$OfficeIpCidr",
    "ENFORCE_IP_ALLOWLIST=$EnforceIpAllowlist"
)
$secretArgs = @("smg-api-key=$apiKey")
if ($hasDirectAutotask) {
    $secretArgs += @(
        "autotask-username=$autotaskUsername",
        "autotask-secret=$autotaskSecret",
        "autotask-integration-code=$autotaskIntegrationCode"
    )
    $envVars += @(
        "AUTOTASK_BASE_URL=$AutotaskBaseUrl",
        "AUTOTASK_USERNAME=secretref:autotask-username",
        "AUTOTASK_SECRET=secretref:autotask-secret",
        "AUTOTASK_INTEGRATION_CODE=secretref:autotask-integration-code"
    )
}

$count = az containerapp list -g $ResourceGroup --query "[?name=='$ContainerAppName'] | length(@)" -o tsv --only-show-errors
$exists = ($count -eq "1")

if ($exists) {
    Write-Host "Updating existing Container App $ContainerAppName..."
    az containerapp secret set -n $ContainerAppName -g $ResourceGroup --secrets $secretArgs | Out-Null
    if ($hasDirectAutotask) {
        az containerapp update -n $ContainerAppName -g $ResourceGroup `
            --image $imageRef `
            --set-env-vars $envVars `
            --cpu 0.25 `
            --memory 0.5Gi `
            --min-replicas 0 `
            --max-replicas 1 | Out-Null
    }
    else {
        az containerapp update -n $ContainerAppName -g $ResourceGroup `
            --image $imageRef `
            --set-env-vars $envVars `
            --remove-env-vars AUTOTASK_BASE_URL AUTOTASK_USERNAME AUTOTASK_SECRET AUTOTASK_INTEGRATION_CODE `
            --cpu 0.25 `
            --memory 0.5Gi `
            --min-replicas 0 `
            --max-replicas 1 | Out-Null

        Write-Host "Cleaning up unused direct Autotask secrets (if present)..."
        $existingSecrets = (az containerapp secret list -n $ContainerAppName -g $ResourceGroup --query "[].name" -o tsv) -split "`n" | ForEach-Object { $_.Trim() } | Where-Object { $_ }
        $candidateSecrets = @($AutotaskUsernameSecretName, $AutotaskSecretSecretName, $AutotaskIntegrationCodeSecretName)
        $toRemove = @($candidateSecrets | Where-Object { $existingSecrets -contains $_ })
        if ($toRemove.Count -gt 0) {
            az containerapp secret remove -n $ContainerAppName -g $ResourceGroup --secret-names $toRemove | Out-Null
        }
    }
}
else {
    Write-Host "Creating Container App $ContainerAppName..."
    az containerapp create -n $ContainerAppName -g $ResourceGroup `
        --environment $envId `
        --image $imageRef `
        --ingress external `
        --target-port 8080 `
        --min-replicas 0 `
        --max-replicas 1 `
        --cpu 0.25 `
        --memory 0.5Gi `
        --registry-server "$AcrName.azurecr.io" `
        --secrets $secretArgs `
        --env-vars $envVars | Out-Null
}

$fqdn = az containerapp show -n $ContainerAppName -g $ResourceGroup --query "properties.configuration.ingress.fqdn" -o tsv

Write-Host ""
Write-Host "Deployment complete."
Write-Host "Adapter URL: https://$fqdn/api/techops"
Write-Host "Health URL : https://$fqdn/healthz"
