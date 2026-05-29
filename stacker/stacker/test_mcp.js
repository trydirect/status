const WebSocket = require('ws');

const ws = new WebSocket('ws://127.0.0.1:8000/mcp', {
    headers: {
        'Authorization': `Bearer ${process.env.BEARER_TOKEN}` // Replace with your actual token
    }
});

ws.on('open', function open() {
    console.log('Connected to MCP server');
    
    // Send tools/list request
    const request = {
        jsonrpc: '2.0',
        id: 1,
        method: 'tools/list',
        params: {}
    };
    
    console.log('Sending request:', JSON.stringify(request));
    ws.send(JSON.stringify(request));
    
    // Close after 5 seconds
    setTimeout(() => {
        ws.close();
        process.exit(0);
    }, 5000);
});

ws.on('message', function message(data) {
    console.log('Received:', data.toString());
});

ws.on('error', function error(err) {
    console.error('Error:', err);
    process.exit(1);
});

ws.on('close', function close() {
    console.log('Connection closed');
});
