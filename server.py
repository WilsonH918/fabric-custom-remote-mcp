import os
import sys
import warnings
import logging
from typing import Any
from pathlib import Path
import json
from dotenv import load_dotenv
import httpx
from azure.identity import OnBehalfOfCredential, ManagedIdentityCredential
from mcp.server.fastmcp import FastMCP
from fastmcp.server.dependencies import get_http_request
from starlette.requests import Request
from starlette.responses import HTMLResponse

# Load environment variables from .env file if present
load_dotenv()

# Reduce MCP SDK, uvicorn, and httpx logging verbosity
logging.getLogger("mcp").setLevel(logging.WARNING)
logging.getLogger("uvicorn").setLevel(logging.WARNING)
logging.getLogger("httpx").setLevel(logging.WARNING)

# Suppress websockets deprecation warnings from uvicorn (not using WebSockets anyways)
warnings.filterwarnings("ignore", category=DeprecationWarning, module="websockets.legacy")
warnings.filterwarnings("ignore", category=DeprecationWarning, module="uvicorn.protocols.websockets")

# Initialize FastMCP server
mcp = FastMCP("fabric", stateless_http=True)

FABRIC_TENANT_ID = os.environ["FABRIC_TENANT_ID"]
FABRIC_CLIENT_ID = os.environ["FABRIC_CLIENT_ID"]
FABRIC_CLIENT_SECRET = os.environ["FABRIC_CLIENT_SECRET"]
FABRIC_USER_OBJECT_ID = os.environ["FABRIC_USER_OBJECT_ID"]
FABRIC_CAPACITY_ID = os.environ["FABRIC_CAPACITY_ID"]
FABRIC_SCOPE = "https://api.fabric.microsoft.com/.default"
FABRIC_BASE = "https://api.fabric.microsoft.com/v1"
PBI_SCOPE = "https://analysis.windows.net/powerbi/api/.default"
PBI_BASE = "https://api.powerbi.com/v1.0/myorg"


HTTPX_TIMEOUT = httpx.Timeout(connect=5.0, read=60.0, write=10.0, pool=5.0)


async def get_fabric_token() -> str:
    token_url = f"https://login.microsoftonline.com/{FABRIC_TENANT_ID}/oauth2/v2.0/token"
    data = {
        "client_id": FABRIC_CLIENT_ID,
        "client_secret": FABRIC_CLIENT_SECRET,
        "grant_type": "client_credentials",
        "scope": FABRIC_SCOPE,
    }

    async with httpx.AsyncClient() as client:
        resp = await client.post(token_url, data=data)
        resp.raise_for_status()
        token = resp.json().get("access_token")
        if not token:
            raise RuntimeError("Failed to get Fabric access token")
        return token
    
async def get_powerbi_token() -> str:
    token_url = f"https://login.microsoftonline.com/{FABRIC_TENANT_ID}/oauth2/v2.0/token"
    data = {
        "client_id": FABRIC_CLIENT_ID,
        "client_secret": FABRIC_CLIENT_SECRET,
        "grant_type": "client_credentials",
        "scope": PBI_SCOPE,
    }

    async with httpx.AsyncClient(timeout=HTTPX_TIMEOUT) as client:
        resp = await client.post(token_url, data=data)
        resp.raise_for_status()
        return resp.json()["access_token"]

    
async def _fabric_headers() -> dict[str, str]:
    token = await get_fabric_token()
    return {"Authorization": f"Bearer {token}", "Content-Type": "application/json"}

async def _pbi_headers() -> dict[str, str]:
    token = await get_powerbi_token()
    return {"Authorization": f"Bearer {token}", "Content-Type": "application/json"}


# ============================
# FABRIC & PBI TOOLS
# ============================

@mcp.tool()
async def list_fabric_workspaces() -> str:
    """
    List all Fabric workspaces using hard-coded credentials.
    Fetches an access token using the service principal, then calls the Fabric API.
    Returns a string listing workspace names and IDs.
    """
    headers = await _fabric_headers()

    async with httpx.AsyncClient(timeout=HTTPX_TIMEOUT) as client:
        resp = await client.get(f"{FABRIC_BASE}/workspaces", headers=headers)
        if resp.status_code != 200:
            return f"Failed to fetch workspaces: {resp.text}"

        workspaces = resp.json().get("value", [])
        if not workspaces:
            return "No Fabric workspaces found."

        output = [f"- {ws['displayName']} (ID: {ws['id']})" for ws in workspaces]
        return "\n".join(output)


@mcp.tool()
async def create_fabric_workspace(name: str) -> str:
    """
    Create a new Fabric workspace with the given name.
    Returns the workspace ID as a string.
    """
    headers = await _fabric_headers()
    payload = {"displayName": name, "capacityId": FABRIC_CAPACITY_ID}

    async with httpx.AsyncClient(timeout=HTTPX_TIMEOUT) as client:
        response = await client.post(f"{FABRIC_BASE}/workspaces", json=payload, headers=headers)

    if response.status_code == 201:
        return str(response.json().get("id", "")).strip().replace("\ufeff", "")
    elif response.status_code == 400 and "already exists" in response.text:
        return f"Workspace '{name}' already exists. Skipping."
    else:
        return f"Error creating workspace '{name}': {response.text}"



@mcp.tool()
async def assign_fabric_workspace_admin(workspace_id: str, user_object_id: str = None) -> str:
    """
    Assign a user as Admin to a Fabric workspace using its ID.
    Defaults to the hard-coded FABRIC_USER_OBJECT_ID if none is provided.
    Returns a human-readable string with the result.
    """
    uid = user_object_id or FABRIC_USER_OBJECT_ID
    if not uid:
        return "Error: user_object_id missing and no FABRIC_USER_OBJECT_ID defined"

    headers = await _fabric_headers()
    payload = {"principal": {"id": uid, "type": "User"}, "role": "Admin"}

    async with httpx.AsyncClient(timeout=HTTPX_TIMEOUT) as client:
        resp = await client.post(
            f"{FABRIC_BASE}/workspaces/{workspace_id}/roleAssignments",
            json=payload,
            headers=headers
        )

        if resp.status_code in (200, 201, 204):
            return f"Successfully assigned user '{uid}' as Admin to workspace '{workspace_id}'"
        return f"Failed to assign Admin. Status: {resp.status_code}, Response: {resp.text}"
  
    
@mcp.tool()
async def list_fabric_datasets(workspace_id: str) -> str:
    """
    List all datasets (semantic models) in a Fabric workspace.
    Returns a formatted string containing dataset names and IDs.
    Examples:
      - 'show datasets in workspace X'
      - 'what datasets are available?'
      - 'list all semantic models'
    """

    headers = await _pbi_headers()

    async with httpx.AsyncClient(timeout=HTTPX_TIMEOUT) as client:
        resp = await client.get(
            f"{PBI_BASE}/groups/{workspace_id}/datasets",
            headers=headers
        )

        if resp.status_code != 200:
            return f"Error fetching datasets: {resp.status_code}\n{resp.text}"

        data = resp.json()
        datasets = data.get("value", [])

        if not datasets:
            return "No datasets found in this workspace."

        output = [f"Found {len(datasets)} datasets:\n"]
        for ds in datasets:
            output.append(f"{ds['name']} (ID: {ds['id']}) (WebUrl: {ds['webUrl']})")

        return "\n".join(output)

@mcp.tool()
async def get_fabric_model_definition(workspace_id: str, dataset_id: str) -> str:
    """
    Retrieve the full TMDL model definition for a Fabric semantic model.
    This includes tables, columns, measures, calculations, and relationships.
    Required before evaluating DAX or modifying models.
    """
    import base64
    import asyncio

    headers = await _fabric_headers()

    # -------- Step 1: Kickoff long-running operation --------
    url = f"{FABRIC_BASE}/workspaces/{workspace_id}/semanticModels/{dataset_id}/getDefinition"

    async with httpx.AsyncClient(timeout=HTTPX_TIMEOUT) as client:
        initial = await client.post(url, headers=headers)

        # If API immediately returns definition
        if initial.status_code == 200:
            result = initial.json()

        # If long-running operation (202)
        elif initial.status_code == 202:
            location = initial.headers.get("Location")
            retry_after = int(initial.headers.get("Retry-After", 15))

            if not location:
                return "Error: Operation returned 202 but no Location header."

            # Poll until finished
            while True:
                await asyncio.sleep(retry_after)

                poll = await client.get(location, headers=headers)

                if poll.status_code in (200, 201):
                    result = poll.json()
                    break
                elif poll.status_code == 202:
                    retry_after = int(poll.headers.get("Retry-After", retry_after))
                    continue
                else:
                    return f"Error polling definition: HTTP {poll.status_code}\n{poll.text}"

        else:
            return f"Error starting definition request: HTTP {initial.status_code}\n{initial.text}"

    # -------- Step 2: Parse TMDL parts --------
    if "definition" not in result:
        return "No model definition returned."

    parts = result["definition"].get("parts", [])
    if not parts:
        return "Model definition exists but contains no parts."

    output = [
        "Dataset Model Definition (TMDL Format)",
        "=" * 50,
        ""
    ]

    for part in parts:
        path = part.get("path", "")
        payload = part.get("payload", "")

        if not path.endswith(".tmdl"):
            continue

        try:
            decoded = base64.b64decode(payload).decode("utf-8")

            output.append("\n" + "─" * 50)
            output.append(f"File: {path}")
            output.append("─" * 50)
            output.append(decoded)

        except Exception as e:
            output.append(f"\nError decoding {path}: {e}")

    return "\n".join(output)

@mcp.tool()
async def execute_fabric_dax_query(workspace_id: str, dataset_id: str, query: str) -> str:
    """
    Execute a DAX query against a Fabric semantic model (dataset).
    Returns formatted query results.

    Examples:
        "EVALUATE SUMMARIZECOLUMNS('Product'[Category], \"@TotalSales\", SUM('Sales'[Amount]))"
        "EVALUATE SUMMARIZECOLUMNS('Date'[Year], 'Date'[Month], \"@Revenue\", SUM('Sales'[Revenue]))"
        "EVALUATE ROW(\"CustomerCount\", COUNTROWS('Customer'))"
    """
    import json

    headers = await _pbi_headers()

    url = f"{PBI_BASE}/groups/{workspace_id}/datasets/{dataset_id}/executeQueries"
    payload = {"queries": [{"query": query}]}

    async with httpx.AsyncClient(timeout=HTTPX_TIMEOUT) as client:
        resp = await client.post(url, json=payload, headers=headers)

        if resp.status_code != 200:
            return f"Error: HTTP {resp.status_code}\n{resp.text}"

        data = resp.json()

    results = data.get("results", [])
    if not results:
        return "No results returned by DAX query."

    first = results[0]

    if "tables" not in first:
        return "DAX executed successfully but returned no table data."

    tables = first["tables"]

    # Pretty-print JSON output
    try:
        return json.dumps(tables, indent=2)
    except Exception:
        return str(tables)

@mcp.tool()
async def list_fabric_reports(workspace_id: str) -> str:
    """
    List all Power BI reports in a workspace using the Power BI REST API.
    Returns report names, IDs, and Web URLs.
    """

    headers = await _pbi_headers()  # Must use Power BI token

    async with httpx.AsyncClient(timeout=HTTPX_TIMEOUT) as client:
        resp = await client.get(
            f"{PBI_BASE}/groups/{workspace_id}/reports",
            headers=headers
        )

    if resp.status_code != 200:
        return f"Error fetching reports: {resp.status_code}\n{resp.text}"

    reports = resp.json().get("value", [])

    if not reports:
        return "No reports found in this workspace."

    output = [f"Found {len(reports)} reports:\n"]
    for r in reports:
        output.append(
            f"{r['name']} "
            f"(ID: {r['id']}) "
            f"(WebUrl: {r.get('webUrl', 'N/A')})"
        )

    return "\n".join(output)


@mcp.tool()
async def create_fabric_lakehouse(workspace_id: str, lakehouse_name: str) -> str:
    """
    Create a new Fabric Lakehouse inside a workspace.
    Returns a success message or error details.
    Example:
        create lakehouse 'SalesLakehouse' in workspace X
    """
    headers = await _fabric_headers()

    url = f"{FABRIC_BASE}/workspaces/{workspace_id}/lakehouses"
    payload = {"displayName": lakehouse_name}

    async with httpx.AsyncClient(timeout=HTTPX_TIMEOUT) as client:
        resp = await client.post(url, json=payload, headers=headers)

    if resp.status_code == 201:
        return f"Lakehouse '{lakehouse_name}' created successfully."

    return f"Error creating lakehouse '{lakehouse_name}': HTTP {resp.status_code}\n{resp.text}"

@mcp.tool()
async def create_fabric_warehouse(workspace_id: str, warehouse_name: str) -> str:
    """
    Create a new Fabric Warehouse inside a workspace.
    Returns a success message or error details.
    Example:
        create warehouse 'FinanceWH' in workspace X
    """
    headers = await _fabric_headers()

    url = f"{FABRIC_BASE}/workspaces/{workspace_id}/warehouses"
    payload = {"displayName": warehouse_name}

    async with httpx.AsyncClient(timeout=HTTPX_TIMEOUT) as client:
        resp = await client.post(url, json=payload, headers=headers)

    if resp.status_code in (201, 202):
        return f"Warehouse '{warehouse_name}' created successfully or creation accepted."

    return f"Error creating warehouse '{warehouse_name}': HTTP {resp.status_code}\n{resp.text}"


@mcp.tool()
async def get_user_info() -> str:
    """
    Demonstrate extracting the bearer token from the incoming Authorization header to exchange for Graph API token.

    Returns:
        String with user info or error message.
    """
    request = get_http_request()

    auth_header = request.headers.get("authorization", "")
    
    if not auth_header:
        return "Error: No access token found in request"
    
    # Extract bearer token (remove "Bearer " prefix if present)
    access_token = auth_header.replace("Bearer ", "").replace("bearer ", "").strip()
        
   # Get required environment variables
    token_exchange_audience = os.environ.get("TokenExchangeAudience", "api://AzureADTokenExchange")
    public_token_exchange_scope = f"{token_exchange_audience}/.default"
    federated_credential_client_id = os.environ.get("OVERRIDE_USE_MI_FIC_ASSERTION_CLIENTID")
    client_id = os.environ.get("WEBSITE_AUTH_CLIENT_ID")
    tenant_id = os.environ.get("WEBSITE_AUTH_AAD_ALLOWED_TENANTS")
    
    try:
        # Create managed identity credential for getting the client assertion
        managed_identity_credential = ManagedIdentityCredential(client_id=federated_credential_client_id)
        
        # Get the client assertion token first
        client_assertion_token = managed_identity_credential.get_token(public_token_exchange_scope)
        
        # Use OBO credential with managed identity assertion
        obo_credential = OnBehalfOfCredential(
            tenant_id=tenant_id,
            client_id=client_id,
            user_assertion=access_token,
            client_assertion_func=lambda: client_assertion_token.token
        )
        
        # Get token for Microsoft Graph
        graph_token = obo_credential.get_token("https://graph.microsoft.com/.default")
        logging.info("Successfully obtained Graph token")
        
        # Call Microsoft Graph API
        async with httpx.AsyncClient() as client:
            response = await client.get(
                "https://graph.microsoft.com/v1.0/me",
                headers={"Authorization": f"Bearer {graph_token.token}"}
            )
            response.raise_for_status()
            user_data = response.json()
            
            logging.info(f"Successfully retrieved user info for: {user_data.get('userPrincipalName', 'N/A')}")
            
            return f"""User Information:
                    - Display Name: {user_data.get('displayName', 'N/A')}
                    - Email: {user_data.get('mail', 'N/A')}
                    - User Principal Name: {user_data.get('userPrincipalName', 'N/A')}
                    - ID: {user_data.get('id', 'N/A')}"""
            
    except Exception as e:
        logging.error(f"Error getting user info: {str(e)}", exc_info=True)
        website_hostname = os.environ.get('WEBSITE_HOSTNAME', '')
        return f"""Error getting user info: {str(e)}
                You're logged in but might need to grant consent to the application.
                Open a browser to the following link to consent:
                https://{website_hostname}/.auth/login/aad?post_login_redirect_uri=https://{website_hostname}/authcomplete"""

# Add a custom route to serve authcomplete.html
@mcp.custom_route("/authcomplete", methods=["GET"])
async def auth_complete(request: Request) -> HTMLResponse:
    """Serve the authcomplete.html file after OAuth redirect."""
    try:
        html_path = Path(__file__).parent / "authcomplete.html"
        logging.info(f"Complete authcomplete.html: {html_path}")
        
        content = html_path.read_text()
        return HTMLResponse(content=content, status_code=200)
    except Exception as e:
        logging.error(f"Error loading authcomplete.html: {str(e)}", exc_info=True)
        return HTMLResponse(
            content="<html><body><h1>Authentication Complete</h1><p>You can close this window.</p></body></html>", 
            status_code=200
        )

if __name__ == "__main__":
    try:
        # Initialize and run the server
        print("Starting MCP server...")
        mcp.run(transport="streamable-http") 
    except Exception as e:
        print(f"Error while running MCP server: {e}", file=sys.stderr)
