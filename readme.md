
```mermaid

flowchart LR
    %% Data Architecture for Custom Remote MCP Server with Fabric and Power BI
    %% References:
    %% - Remote Power BI MCP server enables agents to query semantic models and execute DAX  (turn1search3)
    %% - Azure Functions can host remote MCP servers and provide built in authentication  (turn1search7, turn1search12)
    %% - Flex Consumption plan for serverless autoscale and deployment via azd  (turn1search8)
    %% - Govern and expose MCP servers with API Management  (turn1search11)
    %% - Register custom MCP server in API Center and connect to Foundry Agent Service  (turn1search10)
    %% - Streamable HTTP transport recommended for MCP endpoints  (turn1search12)

    subgraph Client_and_Agent
        Dev[Developer workstation\nVS Code with GitHub Copilot\nAgent Mode]
        Foundry[Microsoft Foundry Agent Service\nRegistered tool via API Center]
    end

    subgraph Azure_Functions_MCP_Server
        AF[Azure Functions App\nCustom Handler hosting server.py]
        Auth[Built in authentication\nMicrosoft Entra ID\nOBO and service principal]
        KV[Azure Key Vault\nSecrets and certificates]
        AI[Application Insights\nTelemetry and traces]
        APIC[Azure API Center or API Management\nCatalog, governance, policies]
    end

    subgraph Fabric_and_PowerBI
        PBI[Power BI and Fabric service\nPublic REST APIs]
        SM[Semantic Models\nSchema discovery\nDAX execution]
        DS[Data sources backing Fabric\nLakehouse\nWarehouse\nEventhouse]
    end

    Dev -- HTTPS MCP\nJSON RPC over streamable HTTP --> AF
    Foundry -- HTTPS MCP\nAuthorized calls --> AF

    AF -- Token acquisition\nOBO or service principal --> Auth
    AF -- Tools: Create Workspace,\nAnalyze Report,\nExecute DAX,\nFix Report --> PBI
    PBI --> SM
    SM --> DS

    AF --- KV
    AF --- AI
    AF --- APIC

    class Dev,Foundry,AF,Auth,KV,AI,APIC,PBI,SM,DS nodeStyle;

    classDef nodeStyle fill:#eff6ff,stroke:#1e3a8a,stroke-width:1px,color:#0f172a,font-size:12px;
---

