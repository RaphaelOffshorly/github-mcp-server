# GitHub MCP Server - SSE Mode

This document describes how to use the GitHub MCP Server in Server-Sent Events (SSE) mode, which allows multiple users to connect with their own GitHub tokens.

## Overview

The SSE mode enables:
- Multiple users connecting simultaneously with their own GitHub Personal Access Tokens
- AES-256 encryption for secure token transmission
- Real-time server-sent events for each connected user
- Individual MCP server instances per user connection

## Setup

### 1. Generate an Encryption Key

First, generate a 32-byte encryption key:

```bash
./github-mcp-server encrypt generate-key
```

This will output something like:
```
Generated encryption key: ABC123XYZ...
Set this as your GITHUB_ENCRYPTION_KEY environment variable
```

### 2. Set Environment Variables

Create a `.env` file or set environment variables:

```bash
export GITHUB_ENCRYPTION_KEY="your-generated-key-here"
export GITHUB_PORT=8080  # Optional, defaults to 8080
```

### 3. Start the SSE Server

```bash
./github-mcp-server sse --port 8080
```

## Usage

### Encrypting GitHub Tokens

Users need to encrypt their GitHub Personal Access Tokens before using them:

```bash
./github-mcp-server encrypt encrypt-token "ghp_your_github_token_here"
```

This will output:
```
Encrypted token: encrypted_token_string_here
Use this encrypted token in your SSE URL: /sse?token=encrypted_token_string_here&encrypted=true
```

### Connecting to SSE Endpoint

Users can connect to the SSE endpoint in several ways:

#### With Encrypted Token
```
GET /sse?token=ENCRYPTED_TOKEN&encrypted=true&user_id=optional_user_id
```

#### With Plain Token (not recommended for production)
```
GET /sse?token=PLAIN_GITHUB_TOKEN&user_id=optional_user_id
```

### Example with curl

```bash
# Connect with encrypted token
curl -N -H "Accept: text/event-stream" \
  "http://localhost:8080/sse?token=ENCRYPTED_TOKEN&encrypted=true&user_id=user123"
```

## Server Endpoints

### SSE Endpoint
- **URL**: `/sse`
- **Method**: GET
- **Parameters**:
  - `token` (required): GitHub Personal Access Token (plain or encrypted)
  - `encrypted` (optional): Set to "true" if token is encrypted
  - `user_id` (optional): Custom user identifier

### Health Check
- **URL**: `/health`
- **Method**: GET
- **Response**: JSON with server status and connection count

### Statistics
- **URL**: `/stats`
- **Method**: GET
- **Response**: JSON with detailed connection statistics

## SSE Events

The server sends the following event types:

### connected
Sent when a user successfully connects:
```
event: connected
data: {"user_id": "user123", "message": "Connected to GitHub MCP Server", "version": "1.0.0"}
```

### ping
Sent every 30 seconds to keep the connection alive:
```
event: ping
data: {"timestamp": 1645123456}
```

### error
Sent when an error occurs:
```
event: error
data: {"message": "error description"}
```

## Security Considerations

1. **Always use HTTPS in production**
2. **Use encrypted tokens** to prevent token exposure in logs
3. **Rotate encryption keys** regularly
4. **Monitor connection logs** for suspicious activity
5. **Set appropriate CORS headers** for your use case

## Command Line Interface

### Generate Encryption Key
```bash
./github-mcp-server encrypt generate-key
```

### Encrypt Token
```bash
./github-mcp-server encrypt encrypt-token "ghp_your_token"
```

### Decrypt Token (for testing)
```bash
./github-mcp-server encrypt decrypt-token "encrypted_token"
```

### Start SSE Server
```bash
./github-mcp-server sse --port 8080
```

## Environment Variables

- `GITHUB_ENCRYPTION_KEY`: 32-byte encryption key (required for SSE mode)
- `GITHUB_PORT`: Port to run SSE server on (default: 8080)
- `GITHUB_HOST`: GitHub Enterprise hostname (optional)
- `GITHUB_TOOLSETS`: Comma-separated list of toolsets to enable
- `GITHUB_READ_ONLY`: Enable read-only mode
- `GITHUB_DYNAMIC_TOOLSETS`: Enable dynamic toolsets
- `GITHUB_ENABLE_COMMAND_LOGGING`: Enable command logging
- `GITHUB_LOG_FILE`: Path to log file

## Integration Examples

### JavaScript/Browser
```javascript
const eventSource = new EventSource(
  'http://localhost:8080/sse?token=ENCRYPTED_TOKEN&encrypted=true&user_id=user123'
);

eventSource.onmessage = function(event) {
  console.log('Received:', event.data);
};

eventSource.addEventListener('connected', function(event) {
  console.log('Connected:', JSON.parse(event.data));
});

eventSource.addEventListener('ping', function(event) {
  console.log('Ping:', JSON.parse(event.data));
});

eventSource.addEventListener('error', function(event) {
  console.error('Error:', JSON.parse(event.data));
});
```

### Python
```python
import requests
import json

url = "http://localhost:8080/sse"
params = {
    "token": "ENCRYPTED_TOKEN",
    "encrypted": "true",
    "user_id": "user123"
}

response = requests.get(url, params=params, stream=True)
for line in response.iter_lines():
    if line:
        print(line.decode('utf-8'))
```

## Troubleshooting

### Common Issues

1. **"encryption key not configured"**: Set the `GITHUB_ENCRYPTION_KEY` environment variable
2. **"token decryption failed"**: Ensure the token was encrypted with the same key
3. **"failed to initialize GitHub connection"**: Check that the GitHub token is valid and has appropriate permissions
4. **Connection drops**: This is normal for SSE; implement reconnection logic in your client

### Debugging

Enable command logging to see detailed request/response logs:
```bash
export GITHUB_ENABLE_COMMAND_LOGGING=true
export GITHUB_LOG_FILE=/path/to/logfile.log
./github-mcp-server sse --port 8080
