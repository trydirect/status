import asyncio
import websockets
import json

async def test_mcp():
    uri = "ws://127.0.0.1:8000/mcp"
    headers = {
        "Authorization": f"Bearer {os.getenv('BEARER_TOKEN')}"
    }
    
    async with websockets.connect(uri, extra_headers=headers) as websocket:
        # Send tools/list request
        request = {
            "jsonrpc": "2.0",
            "id": 1,
            "method": "tools/list",
            "params": {}
        }
        
        print("Sending request:", json.dumps(request))
        await websocket.send(json.dumps(request))
        
        # Wait for response
        response = await websocket.recv()
        print("Response:", response)
        
        # Parse and pretty print
        response_json = json.loads(response)
        print("\nParsed response:")
        print(json.dumps(response_json, indent=2))
        
        if "result" in response_json and "tools" in response_json["result"]:
            tools = response_json["result"]["tools"]
            print(f"\n✓ Found {len(tools)} tools:")
            for tool in tools:
                print(f"  - {tool['name']}: {tool['description']}")

if __name__ == "__main__":
    asyncio.run(test_mcp())
