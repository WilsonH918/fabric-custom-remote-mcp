
# FabricOps Remote MCP Server on Azure Functions

Project goal: expose Microsoft Fabric and Power BI operations to AI agents through a custom remote MCP server hosted on Azure Functions. Tools implemented in `server.py` allow agents to create workspaces, analyze reports, execute DAX, and apply fixes with enterprise governance.

---

## 1. Overview

* Remote MCP server: speaks Model Context Protocol over HTTPS using JSON RPC. An MCP client inside an AI host such as GitHub Copilot in VS Code or Azure AI Foundry Agent Service connects and invokes tools that you define in `server.py`.
* Hosted on Azure Functions: the MCP server runs inside an Azure Functions App. The app exposes the endpoint `/runtime/webhooks/mcp` for streamable http or `/runtime/webhooks/mcp/sse` for SSE. Authentication is handled by built in Azure Functions authentication using Microsoft Entra ID.
* Targets Fabric and Power BI: tools call Fabric and Power BI REST APIs for workspace lifecycle, item metadata, semantic model discovery, and DAX execution.

## 2. Data architecture summary
<img width="1460" height="710" alt="image" src="https://github.com/user-attachments/assets/99179c95-a622-4038-a7ef-da4af8867e75" />

* MCP Host to Function App MCP endpoint: HTTPS MCP JSON RPC. Endpoint `/runtime/webhooks/mcp` or `/runtime/webhooks/mcp/sse`. Authentication Entra ID or a system key.
* Function App MCP server to Fabric and Power BI: HTTPS REST OAuth Bearer. Methods GET POST PUT PATCH DELETE. Use On Behalf Of or a service principal.
* Infra: Storage Account with Private Endpoint and VNet integration in the Flex plan. Key Vault with Managed Identity for secrets.

## 3. `server.py` MCP tools and connection model

`server.py` is the MCP server implementation. It registers tools with typed input and output schemas, handles tool invocation from clients, and calls Fabric and Power BI REST endpoints using OAuth tokens. It runs under Azure Functions so MCP clients can reach it at the app MCP endpoint.

Typical flow:

1. MCP client connects to the Function App MCP endpoint.
2. Client lists tools and selects one.
3. Client invokes a tool with parameters.
4. `server.py` performs REST calls to Fabric or Power BI and returns a structured JSON result.

## 4. Tool to API mapping examples

| MCP tool | Method | Example endpoint | Purpose |
|---|---|---|---|
| CreateWorkspace | POST | `/v1/workspaces` | Provision a workspace with metadata and permissions |
| AnalyzeReport | GET | `/v1/items/{reportId}` | Retrieve report metadata and dataset bindings |
| ExecuteDAX | POST | `/v1/datasets/{datasetId}/executeQueries` | Run DAX against semantic models |
| FixReport | PATCH or PUT | `/v1/items/{reportId}` | Update report properties or binding corrections |

## 5. How agents connect

### GitHub Copilot in VS Code

Add a remote MCP server configuration that points at the Function App MCP endpoint.

```json
{
  "servers": {
    "fabricops-remote": {
      "type": "http",
      "url": "https://<your-functions-host>/runtime/webhooks/mcp",
      "headers": { "Authorization": "Bearer ${input:entra_token}" }
    }
  },
  "inputs": [
    { "type": "promptString", "id": "entra_token", "description": "Microsoft Entra access token", "password": true }
  ]
}
```

The MCP client inside Copilot connects over HTTPS and discovers tools exposed by `server.py`.

### Azure AI Foundry Agent Service

Register the remote MCP endpoint as a tool for your agent. You can pass headers for authentication and catalog the tool with API Center if needed.
<img width="952" height="357" alt="image" src="https://github.com/user-attachments/assets/7804b93f-1494-4a98-84ea-d4edcef59e60" />


## 6. Security and networking

* Built in authentication: use Azure Functions authentication with Entra ID for the MCP endpoint challenge and authorization.
* Flex Consumption with VNet: enable VNet integration so the Function App can reach the Storage Account using a Private Endpoint. You preserve scale to zero.
* Storage Account: required by Functions for runtime state, triggers, and content. Lock public access and use a Private Endpoint.
* Key Vault: use Managed Identity to retrieve secrets such as service principal credentials. Key Vault is not in the data path between the MCP Host and Server.

## 7. Local development and deployment

* Local run: use Azure Functions Core Tools `func start`. Test `/runtime/webhooks/mcp` or `/runtime/webhooks/mcp/sse` depending on your transport.
* Deployment: use Azure Developer CLI `azd up` with infrastructure templates to provision the Flex plan, Storage Private Endpoint, Key Vault, and application settings.

## 8. Repository structure

```
fabric-custom-remote-mcp/
├─ server.py            MCP tools for workspace operations, report analysis, DAX, and fixes
├─ requirements.txt     Python dependencies for MCP, Azure auth, and REST clients
├─ host.json            Functions configuration for the MCP endpoint and handler
├─ infra/               Infrastructure as code for Functions, Storage Private Endpoint, Key Vault, and networking
```

## 9. Example prompts for agents

* Create a Fabric workspace named SalesOps and list its items.
* Run a DAX query against dataset ContosoSales for the top products.
* Analyze the ExecutiveSummary report and suggest fixes for broken visuals.

## 10. References

* Model Context Protocol architecture and client server messaging
  https://learn.microsoft.com/dotnet/ai/get-started-mcp
* Azure Functions hosting for remote MCP servers and endpoints
  https://learn.microsoft.com/azure/azure-functions/functions-mcp-tutorial
* Power BI remote MCP server and DAX execution via agents
  https://learn.microsoft.com/power-bi/developer/mcp/remote-mcp-server-get-started
* API Management and API Center for MCP governance and cataloging
  https://learn.microsoft.com/azure/api-management/mcp-server-overview
* Flex Consumption plan with VNet integration for Functions
  https://learn.microsoft.com/azure/azure-functions/flex-consumption-plan
* Secure Storage Account with Private Endpoint for Functions
  https://learn.microsoft.com/azure/azure-functions/configure-networking-how-to
