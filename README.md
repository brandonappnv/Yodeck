# TechOps Azure Adapter

This service provides a YoDeck-safe JSON endpoint for the Tech Ops Command Center dashboard.

## What it does

- Calls Autotask server-side with direct REST credentials when configured.
- Falls back to SMG-MCP server-side when direct Autotask mode is not configured.
- Normalizes data into a compact dashboard payload.
- Returns last-known-good payload if live fetch fails.
- Supports a 3-minute dashboard polling model.

## Endpoints

- `GET /healthz`
- `GET /api/techops`

## Local run

```powershell
python -m venv .venv
.venv\Scripts\Activate.ps1
pip install -r requirements.txt
$env:SMG_API_KEY = "<your-smg-api-key>"
uvicorn app:app --host 0.0.0.0 --port 8080
```

Direct Autotask mode:

```powershell
$env:AUTOTASK_BASE_URL = "https://webservices15.autotask.net/ATServicesRest/v1.0"
$env:AUTOTASK_USERNAME = "<autotask-api-username>"
$env:AUTOTASK_SECRET = "<autotask-secret>"
$env:AUTOTASK_INTEGRATION_CODE = "<autotask-integration-code>"
uvicorn app:app --host 0.0.0.0 --port 8080
```

## Azure deploy

From this folder:

```powershell
.\deploy_techops_adapter.ps1
```

Optional overrides:

```powershell
.\deploy_techops_adapter.ps1 -ContainerAppName "techops-adapter-prod" -ImageTag "2026-04-22"
```

Enable direct Autotask mode during deploy:

```powershell
.\deploy_techops_adapter.ps1 `
  -AutotaskBaseUrl "https://webservices15.autotask.net/ATServicesRest/v1.0"
```

Expected Key Vault secret names in `smg-mcp-kv` by default:

- `autotask-username`
- `autotask-secret`
- `autotask-integration-code`

## Dashboard wiring

Set your dashboard HTML to use:

```js
window.TECHOPS_API_URL = "https://<adapter-fqdn>/api/techops";
```

Or use query-string override:

`tech-ops-command-center.html?api=https://<adapter-fqdn>/api/techops`

## YoDeck use

- Host the HTML widget in YoDeck.
- Ensure it points to the adapter API URL above.
- Keep refresh interval at 180 seconds.
