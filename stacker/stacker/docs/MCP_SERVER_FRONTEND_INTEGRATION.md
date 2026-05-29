# MCP Server Frontend Integration Guide

## Overview
This document provides comprehensive guidance for integrating the Stacker MCP (Model Context Protocol) server with the ReactJS Stack Builder frontend. The integration enables an AI-powered chat assistant that helps users build and deploy application stacks through natural language interactions.

## Architecture Overview

```
┌──────────────────────────────────────────────────────────────┐
│  React Frontend (Stack Builder UI)                          │
│                                                              │
│  ┌────────────────┐         ┌──────────────────────────┐   │
│  │  Project Form  │◄────────┤  AI Chat Assistant       │   │
│  │  - Name        │  fills  │  - Chat Messages         │   │
│  │  - Services    │◄────────┤  - Input Box             │   │
│  │  - Resources   │         │  - Context Display       │   │
│  │  - Domains     │         │  - Suggestions           │   │
│  └────────────────┘         └──────────────────────────┘   │
│         │                              │                     │
│         │                              │                     │
│         └──────────┬───────────────────┘                     │
│                    │                                         │
│            ┌───────▼───────┐                                │
│            │  MCP Client   │                                │
│            │  (WebSocket)  │                                │
│            └───────────────┘                                │
│                    │                                         │
└────────────────────┼─────────────────────────────────────────┘
                     │ WebSocket (JSON-RPC 2.0)
                     ▼
┌──────────────────────────────────────────────────────────────┐
│  Stacker Backend (MCP Server)                               │
│  - Tool Registry (85+ tools)                                │
│  - Session Management                                       │
│  - OAuth Authentication                                     │
└──────────────────────────────────────────────────────────────┘
```

## Current v0.2.8 Tool Coverage

The MCP server now exposes project/deployment, cloud credential discovery,
container operations, Status Panel agent control, proxy configuration, guest OS
firewall tools, Vault config tools, and remote service secret tools. The remote
secret tools mirror the CLI/API target model:

- `list_remote_secret_targets` — list deployable service/app target codes for a
  project.
- `list_remote_service_secrets` — list metadata for Vault-backed service-scope
  secrets on one target.
- `get_remote_service_secret` — read metadata for one service secret.
- `set_remote_service_secret` — write one service secret value to Vault.
- `delete_remote_service_secret` — delete one service secret.

Remote secret reads are metadata-only; plaintext values are written to Vault but
never returned to MCP clients.

`get_remote_service_secret` and `list_remote_service_secrets` now include
`secure: true` in their metadata payloads because Vault-backed service secrets
are explicitly classified as secure inputs, not merely inferred by name.

Every MCP tool call is checked against Casbin before its handler executes. Clients
must have a `CALL` policy for `/mcp/tools/<tool_name>`. Marketplace admin tools
are granted only to `group_admin`; regular project, deployment, cloud,
container, proxy, firewall, Vault, and remote-secret tools use the normal user
group policies plus their existing project/ownership checks.

`set_remote_service_secret` and `delete_remote_service_secret` are sensitive
write operations. They also require:

- Casbin permission for `/mcp/tools/set_remote_service_secret` or
  `/mcp/tools/delete_remote_service_secret` with action `CALL`.
- A verified 2FA/MFA marker from the authenticated user profile or access token
  (`mfa_verified`, `two_factor_verified`, `amr` containing `totp`, `otp`,
  `webauthn`, etc.).

## Canonical deployment AI workflow

For deployment troubleshooting and safe automation, frontend clients should
prefer the newer structured deployment tools over older summary payloads:

- `get_deployment_state` for canonical deployment state.
- `explain_topology` and `explain_env` for path and env provenance reasoning.
- `get_deployment_plan` for preview plus stale-plan fingerprint generation.
- `apply_deployment_plan` for confirmed deploy-app and rollback execution.
- `get_deployment_events` for progress, failure, and remediation signals.

### Compatibility and safety rules

1. Do not depend on `get_deployment_status` returning the raw internal
   deployment row. Use `get_deployment_state`, `get_deployment_plan`, and
   `get_deployment_events` when the client needs stable machine-readable fields.
2. Add `apply_deployment_plan` to the frontend confirmation-required tool list.
   The tool requires:
   - `confirm=true`
   - `expected_fingerprint` from the immediately preceding preview
   - a step-up/MFA-capable user session
3. MCP tool failures are returned as successful JSON-RPC envelopes with
   `result.isError=true` and a typed error JSON string in
   `result.content[0].text`. Frontends should parse and surface that typed error
   envelope instead of collapsing it into generic text.
4. Server-side MCP intentionally supports `deploy_app` and `rollback_deploy`
   applies only. Full `deploy` apply still requires local CLI workspace context
   and is rejected with a typed `invalid_request` error.

See [AI deployment workflows](AI_DEPLOYMENT_WORKFLOWS.md) for the documented
tool sequence and evaluation fixture reference.

## Environment inspection contract

`get_app_env_vars` now returns two complementary shapes:

- `environment_variables` — the legacy redacted key/value object for existing
  clients.
- `environment_entries` — the canonical per-variable list for newer clients.

Each `environment_entries` item contains:

- `name`
- `value`
- `secure`
- `redacted`
- `source` (`project` or `vault`)

Frontend clients should prefer `environment_entries` when they need to
distinguish between:

- a value redacted because it is explicitly Vault-backed (`secure=true`)
- a value redacted by legacy heuristic name matching
- a regular project-defined env value

This allows names such as `MYSECURE_PASSPHRASE` to remain safely redacted even
when the key name itself would not match an older secret heuristic.

## Technology Stack

### Core Dependencies

```json
{
  "dependencies": {
    "@modelcontextprotocol/sdk": "^0.5.0",
    "react": "^18.2.0",
    "react-dom": "^18.2.0",
    "zustand": "^4.4.0",
    "@tanstack/react-query": "^5.0.0",
    "ws": "^8.16.0"
  },
  "devDependencies": {
    "@types/react": "^18.2.0",
    "@types/ws": "^8.5.0",
    "typescript": "^5.0.0"
  }
}
```

### TypeScript Configuration

```json
{
  "compilerOptions": {
    "target": "ES2020",
    "lib": ["ES2020", "DOM", "DOM.Iterable"],
    "jsx": "react-jsx",
    "module": "ESNext",
    "moduleResolution": "bundler",
    "resolveJsonModule": true,
    "allowJs": true,
    "strict": true,
    "esModuleInterop": true,
    "skipLibCheck": true
  }
}
```

---

## Phase 1: MCP Client Setup (Week 1)

### 1.1 WebSocket Client

```typescript
// src/lib/mcp/client.ts
import { Client } from '@modelcontextprotocol/sdk/client/index.js';
import { WebSocketClientTransport } from '@modelcontextprotocol/sdk/client/websocket.js';

export interface McpClientConfig {
  url: string;
  authToken: string;
}

export class StackerMcpClient {
  private client: Client | null = null;
  private transport: WebSocketClientTransport | null = null;
  private config: McpClientConfig;
  
  constructor(config: McpClientConfig) {
    this.config = config;
  }
  
  async connect(): Promise<void> {
    // Create WebSocket transport with auth headers
    this.transport = new WebSocketClientTransport(
      new URL(this.config.url),
      {
        headers: {
          'Authorization': `Bearer ${this.config.authToken}`
        }
      }
    );
    
    // Initialize MCP client
    this.client = new Client(
      {
        name: 'stacker-ui',
        version: '1.0.0',
      },
      {
        capabilities: {
          tools: {}
        }
      }
    );
    
    // Connect to server
    await this.client.connect(this.transport);
    
    console.log('MCP client connected');
  }
  
  async disconnect(): Promise<void> {
    if (this.client) {
      await this.client.close();
      this.client = null;
    }
    if (this.transport) {
      await this.transport.close();
      this.transport = null;
    }
  }
  
  async listTools(): Promise<Array<{
    name: string;
    description: string;
    inputSchema: any;
  }>> {
    if (!this.client) {
      throw new Error('MCP client not connected');
    }
    
    const response = await this.client.listTools();
    return response.tools;
  }
  
  async callTool(
    name: string,
    args: Record<string, any>
  ): Promise<{
    content: Array<{ type: string; text?: string; data?: string }>;
    isError?: boolean;
  }> {
    if (!this.client) {
      throw new Error('MCP client not connected');
    }
    
    const response = await this.client.callTool({
      name,
      arguments: args
    });
    
    return response;
  }
  
  isConnected(): boolean {
    return this.client !== null;
  }
}
```

### 1.2 MCP Context Provider

```typescript
// src/contexts/McpContext.tsx
import React, { createContext, useContext, useEffect, useState } from 'react';
import { StackerMcpClient } from '@/lib/mcp/client';
import { useAuth } from '@/hooks/useAuth';

interface McpContextValue {
  client: StackerMcpClient | null;
  isConnected: boolean;
  error: string | null;
  reconnect: () => Promise<void>;
}

const McpContext = createContext<McpContextValue | undefined>(undefined);

export const McpProvider: React.FC<{ children: React.ReactNode }> = ({ children }) => {
  const { token } = useAuth();
  const [client, setClient] = useState<StackerMcpClient | null>(null);
  const [isConnected, setIsConnected] = useState(false);
  const [error, setError] = useState<string | null>(null);
  
  const connect = async () => {
    if (!token) {
      setError('Authentication required');
      return;
    }
    
    try {
      const mcpClient = new StackerMcpClient({
        url: process.env.REACT_APP_MCP_URL || 'ws://localhost:8000/mcp',
        authToken: token
      });
      
      await mcpClient.connect();
      setClient(mcpClient);
      setIsConnected(true);
      setError(null);
    } catch (err) {
      setError(err instanceof Error ? err.message : 'Connection failed');
      setIsConnected(false);
    }
  };
  
  const reconnect = async () => {
    if (client) {
      await client.disconnect();
    }
    await connect();
  };
  
  useEffect(() => {
    connect();
    
    return () => {
      if (client) {
        client.disconnect();
      }
    };
  }, [token]);
  
  return (
    <McpContext.Provider value={{ client, isConnected, error, reconnect }}>
      {children}
    </McpContext.Provider>
  );
};

export const useMcp = () => {
  const context = useContext(McpContext);
  if (!context) {
    throw new Error('useMcp must be used within McpProvider');
  }
  return context;
};
```

### 1.3 Connection Setup in App

```typescript
// src/App.tsx
import { McpProvider } from '@/contexts/McpContext';
import { AuthProvider } from '@/contexts/AuthContext';
import { QueryClient, QueryClientProvider } from '@tanstack/react-query';

const queryClient = new QueryClient();

function App() {
  return (
    <QueryClientProvider client={queryClient}>
      <AuthProvider>
        <McpProvider>
          <YourAppRoutes />
        </McpProvider>
      </AuthProvider>
    </QueryClientProvider>
  );
}

export default App;
```

---

## Phase 2: Chat Interface Components (Week 2)

### 2.1 Chat Message Types

```typescript
// src/types/chat.ts
export interface ChatMessage {
  id: string;
  role: 'user' | 'assistant' | 'system';
  content: string;
  timestamp: Date;
  toolCalls?: ToolCall[];
  metadata?: {
    projectId?: number;
    step?: number;
    suggestions?: string[];
  };
}

export interface ToolCall {
  id: string;
  toolName: string;
  arguments: Record<string, any>;
  result?: {
    success: boolean;
    data?: any;
    error?: string;
  };
  status: 'pending' | 'completed' | 'failed';
}

export interface ChatContext {
  currentProject?: {
    id?: number;
    name?: string;
    apps?: any[];
    step?: number;
  };
  lastAction?: string;
  availableTools?: string[];
}
```

### 2.2 Chat Store (Zustand)

```typescript
// src/stores/chatStore.ts
import { create } from 'zustand';
import { ChatMessage, ChatContext } from '@/types/chat';

interface ChatStore {
  messages: ChatMessage[];
  context: ChatContext;
  isProcessing: boolean;
  
  addMessage: (message: Omit<ChatMessage, 'id' | 'timestamp'>) => void;
  updateMessage: (id: string, updates: Partial<ChatMessage>) => void;
  clearMessages: () => void;
  setContext: (context: Partial<ChatContext>) => void;
  setProcessing: (processing: boolean) => void;
}

export const useChatStore = create<ChatStore>((set) => ({
  messages: [],
  context: {},
  isProcessing: false,
  
  addMessage: (message) =>
    set((state) => ({
      messages: [
        ...state.messages,
        {
          ...message,
          id: crypto.randomUUID(),
          timestamp: new Date(),
        },
      ],
    })),
  
  updateMessage: (id, updates) =>
    set((state) => ({
      messages: state.messages.map((msg) =>
        msg.id === id ? { ...msg, ...updates } : msg
      ),
    })),
  
  clearMessages: () => set({ messages: [], context: {} }),
  
  setContext: (context) =>
    set((state) => ({
      context: { ...state.context, ...context },
    })),
  
  setProcessing: (processing) => set({ isProcessing: processing }),
}));
```

### 2.3 Chat Sidebar Component

```tsx
// src/components/chat/ChatSidebar.tsx
import React, { useRef, useEffect } from 'react';
import { useChatStore } from '@/stores/chatStore';
import { ChatMessage } from './ChatMessage';
import { ChatInput } from './ChatInput';
import { ChatHeader } from './ChatHeader';

export const ChatSidebar: React.FC = () => {
  const messages = useChatStore((state) => state.messages);
  const messagesEndRef = useRef<HTMLDivElement>(null);
  
  useEffect(() => {
    messagesEndRef.current?.scrollIntoView({ behavior: 'smooth' });
  }, [messages]);
  
  return (
    <div className="flex flex-col h-full bg-white border-l border-gray-200">
      <ChatHeader />
      
      <div className="flex-1 overflow-y-auto p-4 space-y-4">
        {messages.length === 0 ? (
          <div className="flex flex-col items-center justify-center h-full text-gray-500">
            <svg className="w-16 h-16 mb-4" fill="none" viewBox="0 0 24 24" stroke="currentColor">
              <path strokeLinecap="round" strokeLinejoin="round" strokeWidth={2} 
                d="M8 10h.01M12 10h.01M16 10h.01M9 16H5a2 2 0 01-2-2V6a2 2 0 012-2h14a2 2 0 012 2v8a2 2 0 01-2 2h-5l-5 5v-5z" />
            </svg>
            <p className="text-lg font-medium">Ask me anything!</p>
            <p className="text-sm mt-2 text-center px-4">
              I can help you create projects, suggest configurations,<br />
              and deploy your applications to the cloud.
            </p>
          </div>
        ) : (
          messages.map((message) => (
            <ChatMessage key={message.id} message={message} />
          ))
        )}
        <div ref={messagesEndRef} />
      </div>
      
      <ChatInput />
    </div>
  );
};
```

### 2.4 Chat Message Component

```tsx
// src/components/chat/ChatMessage.tsx
import React from 'react';
import { ChatMessage as ChatMessageType } from '@/types/chat';
import { ToolCallDisplay } from './ToolCallDisplay';
import ReactMarkdown from 'react-markdown';

interface Props {
  message: ChatMessageType;
}

export const ChatMessage: React.FC<Props> = ({ message }) => {
  const isUser = message.role === 'user';
  
  return (
    <div className={`flex ${isUser ? 'justify-end' : 'justify-start'}`}>
      <div
        className={`max-w-[85%] rounded-lg px-4 py-2 ${
          isUser
            ? 'bg-blue-600 text-white'
            : 'bg-gray-100 text-gray-900'
        }`}
      >
        {!isUser && (
          <div className="flex items-center mb-1">
            <svg className="w-4 h-4 mr-2" fill="currentColor" viewBox="0 0 20 20">
              <path d="M2 5a2 2 0 012-2h7a2 2 0 012 2v4a2 2 0 01-2 2H9l-3 3v-3H4a2 2 0 01-2-2V5z" />
            </svg>
            <span className="text-xs font-semibold text-gray-600">AI Assistant</span>
          </div>
        )}
        
        <div className="prose prose-sm max-w-none">
          <ReactMarkdown>{message.content}</ReactMarkdown>
        </div>
        
        {message.toolCalls && message.toolCalls.length > 0 && (
          <div className="mt-2 space-y-2">
            {message.toolCalls.map((toolCall) => (
              <ToolCallDisplay key={toolCall.id} toolCall={toolCall} />
            ))}
          </div>
        )}
        
        <div className="text-xs opacity-75 mt-1">
          {message.timestamp.toLocaleTimeString()}
        </div>
      </div>
    </div>
  );
};
```

### 2.5 Chat Input Component

```tsx
// src/components/chat/ChatInput.tsx
import React, { useState } from 'react';
import { useChatStore } from '@/stores/chatStore';
import { useAiAssistant } from '@/hooks/useAiAssistant';

export const ChatInput: React.FC = () => {
  const [input, setInput] = useState('');
  const isProcessing = useChatStore((state) => state.isProcessing);
  const { sendMessage } = useAiAssistant();
  
  const handleSubmit = async (e: React.FormEvent) => {
    e.preventDefault();
    if (!input.trim() || isProcessing) return;
    
    await sendMessage(input);
    setInput('');
  };
  
  return (
    <form onSubmit={handleSubmit} className="border-t border-gray-200 p-4">
      <div className="flex gap-2">
        <input
          type="text"
          value={input}
          onChange={(e) => setInput(e.target.value)}
          placeholder="Ask me to create a project, suggest resources..."
          disabled={isProcessing}
          className="flex-1 rounded-lg border border-gray-300 px-4 py-2 focus:outline-none focus:ring-2 focus:ring-blue-500 disabled:bg-gray-100"
        />
        <button
          type="submit"
          disabled={isProcessing || !input.trim()}
          className="px-6 py-2 bg-blue-600 text-white rounded-lg hover:bg-blue-700 disabled:bg-gray-300 disabled:cursor-not-allowed"
        >
          {isProcessing ? (
            <svg className="animate-spin h-5 w-5" viewBox="0 0 24 24">
              <circle className="opacity-25" cx="12" cy="12" r="10" stroke="currentColor" strokeWidth="4" fill="none" />
              <path className="opacity-75" fill="currentColor" d="M4 12a8 8 0 018-8V0C5.373 0 0 5.373 0 12h4zm2 5.291A7.962 7.962 0 014 12H0c0 3.042 1.135 5.824 3 7.938l3-2.647z" />
            </svg>
          ) : (
            'Send'
          )}
        </button>
      </div>
      
      <div className="mt-2 flex gap-2 flex-wrap">
        <QuickAction action="Create WordPress site" />
        <QuickAction action="Suggest resources for Node.js" />
        <QuickAction action="Show my projects" />
      </div>
    </form>
  );
};

const QuickAction: React.FC<{ action: string }> = ({ action }) => {
  const { sendMessage } = useAiAssistant();
  
  return (
    <button
      onClick={() => sendMessage(action)}
      className="text-xs px-3 py-1 bg-gray-100 hover:bg-gray-200 rounded-full text-gray-700"
    >
      {action}
    </button>
  );
};
```

---

## Phase 3: AI Assistant Hook (Week 3)

### 3.1 AI Assistant Logic

```typescript
// src/hooks/useAiAssistant.ts
import { useMcp } from '@/contexts/McpContext';
import { useChatStore } from '@/stores/chatStore';
import { OpenAI } from 'openai';

const openai = new OpenAI({
  apiKey: process.env.REACT_APP_OPENAI_API_KEY,
  dangerouslyAllowBrowser: true // Only for demo; use backend proxy in production
});

export const useAiAssistant = () => {
  const { client } = useMcp();
  const addMessage = useChatStore((state) => state.addMessage);
  const updateMessage = useChatStore((state) => state.updateMessage);
  const setProcessing = useChatStore((state) => state.setProcessing);
  const context = useChatStore((state) => state.context);
  const messages = useChatStore((state) => state.messages);
  
  const sendMessage = async (userMessage: string) => {
    if (!client?.isConnected()) {
      addMessage({
        role: 'system',
        content: 'MCP connection lost. Please refresh the page.',
      });
      return;
    }
    
    // Add user message
    addMessage({
      role: 'user',
      content: userMessage,
    });
    
    setProcessing(true);
    
    try {
      // Get available tools from MCP server
      const tools = await client.listTools();
      
      // Convert MCP tools to OpenAI function format
      const openaiTools = tools.map((tool) => ({
        type: 'function' as const,
        function: {
          name: tool.name,
          description: tool.description,
          parameters: tool.inputSchema,
        },
      }));
      
      // Build conversation history for OpenAI
      const conversationMessages = [
        {
          role: 'system' as const,
          content: buildSystemPrompt(context),
        },
        ...messages.slice(-10).map((msg) => ({
          role: msg.role as 'user' | 'assistant',
          content: msg.content,
        })),
        {
          role: 'user' as const,
          content: userMessage,
        },
      ];
      
      // Call OpenAI with tools
      const response = await openai.chat.completions.create({
        model: 'gpt-4-turbo-preview',
        messages: conversationMessages,
        tools: openaiTools,
        tool_choice: 'auto',
      });
      
      const assistantMessage = response.choices[0].message;
      
      // Handle tool calls
      if (assistantMessage.tool_calls) {
        const messageId = crypto.randomUUID();
        
        addMessage({
          role: 'assistant',
          content: 'Let me help you with that...',
          toolCalls: assistantMessage.tool_calls.map((tc) => ({
            id: tc.id,
            toolName: tc.function.name,
            arguments: JSON.parse(tc.function.arguments),
            status: 'pending' as const,
          })),
        });
        
        // Execute tools via MCP
        for (const toolCall of assistantMessage.tool_calls) {
          try {
            const result = await client.callTool(
              toolCall.function.name,
              JSON.parse(toolCall.function.arguments)
            );
            
            updateMessage(messageId, {
              toolCalls: assistantMessage.tool_calls.map((tc) =>
                tc.id === toolCall.id
                  ? {
                      id: tc.id,
                      toolName: tc.function.name,
                      arguments: JSON.parse(tc.function.arguments),
                      result: {
                        success: !result.isError,
                        data: result.content[0].text,
                      },
                      status: 'completed' as const,
                    }
                  : tc
              ),
            });
            
            // Parse result and update context
            if (toolCall.function.name === 'create_project' && result.content[0].text) {
              const project = JSON.parse(result.content[0].text);
              useChatStore.getState().setContext({
                currentProject: {
                  id: project.id,
                  name: project.name,
                  apps: project.apps,
                },
              });
            }
          } catch (error) {
            updateMessage(messageId, {
              toolCalls: assistantMessage.tool_calls.map((tc) =>
                tc.id === toolCall.id
                  ? {
                      id: tc.id,
                      toolName: tc.function.name,
                      arguments: JSON.parse(tc.function.arguments),
                      result: {
                        success: false,
                        error: error instanceof Error ? error.message : 'Unknown error',
                      },
                      status: 'failed' as const,
                    }
                  : tc
              ),
            });
          }
        }
        
        // Get final response after tool execution
        const finalResponse = await openai.chat.completions.create({
          model: 'gpt-4-turbo-preview',
          messages: [
            ...conversationMessages,
            assistantMessage,
            ...assistantMessage.tool_calls.map((tc) => ({
              role: 'tool' as const,
              tool_call_id: tc.id,
              content: 'Tool executed successfully',
            })),
          ],
        });
        
        addMessage({
          role: 'assistant',
          content: finalResponse.choices[0].message.content || 'Done!',
        });
      } else {
        // No tool calls, just add assistant response
        addMessage({
          role: 'assistant',
          content: assistantMessage.content || 'I understand. How can I help further?',
        });
      }
    } catch (error) {
      addMessage({
        role: 'system',
        content: `Error: ${error instanceof Error ? error.message : 'Unknown error'}`,
      });
    } finally {
      setProcessing(false);
    }
  };
  
  return { sendMessage };
};

function buildSystemPrompt(context: any): string {
  return `You are an AI assistant for the Stacker platform, helping users build and deploy Docker-based application stacks.

Current context:
${context.currentProject ? `- Working on project: "${context.currentProject.name}" (ID: ${context.currentProject.id})` : '- No active project'}
${context.lastAction ? `- Last action: ${context.lastAction}` : ''}

You can help users with:
1. Creating new projects with multiple services
2. Suggesting appropriate resource limits (CPU, RAM, storage)
3. Listing available templates (WordPress, Node.js, Django, etc.)
4. Deploying projects to cloud providers
5. Managing cloud credentials
6. Validating domains and ports

Always be helpful, concise, and guide users through multi-step processes one step at a time.
When creating projects, ask for all necessary details before calling the create_project tool.`;
}
```

---

## Phase 4: Form Integration (Week 4)

### 4.1 Enhanced Project Form with AI

```tsx
// src/components/project/ProjectFormWithAI.tsx
import React, { useState } from 'react';
import { useChatStore } from '@/stores/chatStore';
import { ChatSidebar } from '@/components/chat/ChatSidebar';
import { ProjectForm } from '@/components/project/ProjectForm';

export const ProjectFormWithAI: React.FC = () => {
  const [showChat, setShowChat] = useState(true);
  const context = useChatStore((state) => state.context);
  
  // Auto-fill form from AI context
  const formData = context.currentProject || {
    name: '',
    apps: [],
  };
  
  return (
    <div className="flex h-screen">
      {/* Main Form Area */}
      <div className="flex-1 overflow-auto">
        <div className="max-w-4xl mx-auto p-8">
          <div className="flex justify-between items-center mb-6">
            <h1 className="text-3xl font-bold">Create New Project</h1>
            <button
              onClick={() => setShowChat(!showChat)}
              className="flex items-center gap-2 px-4 py-2 bg-blue-600 text-white rounded-lg hover:bg-blue-700"
            >
              <svg className="w-5 h-5" fill="none" viewBox="0 0 24 24" stroke="currentColor">
                <path strokeLinecap="round" strokeLinejoin="round" strokeWidth={2} 
                  d="M8 10h.01M12 10h.01M16 10h.01M9 16H5a2 2 0 01-2-2V6a2 2 0 012-2h14a2 2 0 012 2v8a2 2 0 01-2 2h-5l-5 5v-5z" />
              </svg>
              {showChat ? 'Hide' : 'Show'} AI Assistant
            </button>
          </div>
          
          <ProjectForm initialData={formData} />
        </div>
      </div>
      
      {/* Chat Sidebar */}
      {showChat && (
        <div className="w-96 h-screen">
          <ChatSidebar />
        </div>
      )}
    </div>
  );
};
```

### 4.2 Progressive Form Steps

```tsx
// src/components/project/ProgressiveProjectForm.tsx
import React, { useState } from 'react';
import { useAiAssistant } from '@/hooks/useAiAssistant';
import { useChatStore } from '@/stores/chatStore';

const STEPS = [
  { id: 1, name: 'Basic Info', description: 'Project name and description' },
  { id: 2, name: 'Services', description: 'Add applications and Docker images' },
  { id: 3, name: 'Resources', description: 'Configure CPU, RAM, and storage' },
  { id: 4, name: 'Networking', description: 'Set up domains and ports' },
  { id: 5, name: 'Review', description: 'Review and deploy' },
];

export const ProgressiveProjectForm: React.FC = () => {
  const [currentStep, setCurrentStep] = useState(1);
  const context = useChatStore((state) => state.context);
  const { sendMessage } = useAiAssistant();
  
  const project = context.currentProject || {
    name: '',
    description: '',
    apps: [],
  };
  
  const handleAiSuggestion = (prompt: string) => {
    sendMessage(prompt);
  };
  
  return (
    <div className="max-w-4xl mx-auto p-8">
      {/* Progress Stepper */}
      <div className="mb-8">
        <div className="flex justify-between">
          {STEPS.map((step, index) => (
            <div
              key={step.id}
              className={`flex-1 ${index !== STEPS.length - 1 ? 'border-r-2' : ''} ${
                step.id === currentStep
                  ? 'border-blue-600'
                  : step.id < currentStep
                  ? 'border-green-600'
                  : 'border-gray-300'
              }`}
            >
              <div className="flex flex-col items-center pb-4">
                <div
                  className={`w-10 h-10 rounded-full flex items-center justify-center font-bold ${
                    step.id === currentStep
                      ? 'bg-blue-600 text-white'
                      : step.id < currentStep
                      ? 'bg-green-600 text-white'
                      : 'bg-gray-300 text-gray-600'
                  }`}
                >
                  {step.id < currentStep ? '✓' : step.id}
                </div>
                <div className="text-sm font-medium mt-2">{step.name}</div>
                <div className="text-xs text-gray-500 text-center">{step.description}</div>
              </div>
            </div>
          ))}
        </div>
      </div>
      
      {/* AI Suggestions */}
      <div className="mb-6 p-4 bg-blue-50 border border-blue-200 rounded-lg">
        <div className="flex items-start gap-3">
          <svg className="w-6 h-6 text-blue-600 flex-shrink-0 mt-0.5" fill="currentColor" viewBox="0 0 20 20">
            <path d="M9.049 2.927c.3-.921 1.603-.921 1.902 0l1.07 3.292a1 1 0 00.95.69h3.462c.969 0 1.371 1.24.588 1.81l-2.8 2.034a1 1 0 00-.364 1.118l1.07 3.292c.3.921-.755 1.688-1.54 1.118l-2.8-2.034a1 1 0 00-1.175 0l-2.8 2.034c-.784.57-1.838-.197-1.539-1.118l1.07-3.292a1 1 0 00-.364-1.118L2.98 8.72c-.783-.57-.38-1.81.588-1.81h3.461a1 1 0 00.951-.69l1.07-3.292z" />
          </svg>
          <div className="flex-1">
            <p className="text-sm font-medium text-blue-900 mb-2">
              AI Suggestion for Step {currentStep}:
            </p>
            {currentStep === 1 && (
              <button
                onClick={() => handleAiSuggestion('Suggest a good name for a WordPress blog project')}
                className="text-sm text-blue-700 hover:underline"
              >
                Need help naming your project?
              </button>
            )}
            {currentStep === 2 && (
              <button
                onClick={() => handleAiSuggestion('What services do I need for a typical WordPress site?')}
                className="text-sm text-blue-700 hover:underline"
              >
                Not sure which services to add?
              </button>
            )}
            {currentStep === 3 && (
              <button
                onClick={() =>
                  handleAiSuggestion(
                    `Suggest appropriate resources for ${project.apps.length} services: ${project.apps.map((a: any) => a.name).join(', ')}`
                  )
                }
                className="text-sm text-blue-700 hover:underline"
              >
                Let AI suggest resource limits
              </button>
            )}
          </div>
        </div>
      </div>
      
      {/* Step Content */}
      <div className="bg-white p-6 rounded-lg shadow">
        {currentStep === 1 && <BasicInfoStep />}
        {currentStep === 2 && <ServicesStep />}
        {currentStep === 3 && <ResourcesStep />}
        {currentStep === 4 && <NetworkingStep />}
        {currentStep === 5 && <ReviewStep />}
      </div>
      
      {/* Navigation */}
      <div className="mt-6 flex justify-between">
        <button
          onClick={() => setCurrentStep(Math.max(1, currentStep - 1))}
          disabled={currentStep === 1}
          className="px-6 py-2 border border-gray-300 rounded-lg hover:bg-gray-50 disabled:opacity-50"
        >
          Previous
        </button>
        <button
          onClick={() => setCurrentStep(Math.min(STEPS.length, currentStep + 1))}
          disabled={currentStep === STEPS.length}
          className="px-6 py-2 bg-blue-600 text-white rounded-lg hover:bg-blue-700 disabled:opacity-50"
        >
          {currentStep === STEPS.length ? 'Deploy' : 'Next'}
        </button>
      </div>
    </div>
  );
};
```

---

## Phase 5: Testing & Optimization (Week 5)

### 5.1 Unit Tests

```typescript
// src/lib/mcp/__tests__/client.test.ts
import { describe, it, expect, beforeEach, afterEach } from 'vitest';
import { StackerMcpClient } from '../client';

describe('StackerMcpClient', () => {
  let client: StackerMcpClient;
  
  beforeEach(() => {
    client = new StackerMcpClient({
      url: 'ws://localhost:8000/mcp',
      authToken: 'test-token',
    });
  });
  
  afterEach(async () => {
    if (client.isConnected()) {
      await client.disconnect();
    }
  });
  
  it('should connect successfully', async () => {
    await client.connect();
    expect(client.isConnected()).toBe(true);
  });
  
  it('should list available tools', async () => {
    await client.connect();
    const tools = await client.listTools();
    
    expect(tools).toBeInstanceOf(Array);
    expect(tools.length).toBeGreaterThan(0);
    expect(tools[0]).toHaveProperty('name');
    expect(tools[0]).toHaveProperty('description');
  });
  
  it('should call create_project tool', async () => {
    await client.connect();
    
    const result = await client.callTool('create_project', {
      name: 'Test Project',
      apps: [
        {
          name: 'web',
          dockerImage: { repository: 'nginx' },
        },
      ],
    });
    
    expect(result.content).toBeInstanceOf(Array);
    expect(result.isError).toBeFalsy();
  });
});
```

### 5.2 Integration Tests

```typescript
// src/components/chat/__tests__/ChatSidebar.integration.test.tsx
import { render, screen, waitFor } from '@testing-library/react';
import userEvent from '@testing-library/user-event';
import { ChatSidebar } from '../ChatSidebar';
import { McpProvider } from '@/contexts/McpContext';

describe('ChatSidebar Integration', () => {
  it('should send message and receive response', async () => {
    render(
      <McpProvider>
        <ChatSidebar />
      </McpProvider>
    );
    
    const input = screen.getByPlaceholderText(/ask me to create/i);
    const sendButton = screen.getByRole('button', { name: /send/i });
    
    await userEvent.type(input, 'Create a WordPress project');
    await userEvent.click(sendButton);
    
    await waitFor(() => {
      expect(screen.getByText('Create a WordPress project')).toBeInTheDocument();
    });
    
    await waitFor(() => {
      expect(screen.getByText(/let me help/i)).toBeInTheDocument();
    }, { timeout: 5000 });
  });
});
```

### 5.3 Performance Optimization

```typescript
// src/lib/mcp/optimizations.ts

// 1. Debounce AI calls to prevent spam
import { useMemo } from 'react';
import debounce from 'lodash/debounce';

export const useDebouncedAi = () => {
  const { sendMessage } = useAiAssistant();
  
  const debouncedSend = useMemo(
    () => debounce(sendMessage, 500),
    [sendMessage]
  );
  
  return { sendMessage: debouncedSend };
};

// 2. Cache tool list
export const useToolsCache = () => {
  const { client } = useMcp();
  const { data: tools, isLoading } = useQuery({
    queryKey: ['mcp-tools'],
    queryFn: () => client?.listTools(),
    staleTime: 5 * 60 * 1000, // 5 minutes
    enabled: !!client?.isConnected(),
  });
  
  return { tools, isLoading };
};

// 3. Lazy load chat component
import { lazy, Suspense } from 'react';

const ChatSidebar = lazy(() => import('@/components/chat/ChatSidebar'));

export const LazyChat = () => (
  <Suspense fallback={<ChatSkeleton />}>
    <ChatSidebar />
  </Suspense>
);
```

---

## Environment Configuration

### Production Setup

```bash
# .env.production
REACT_APP_MCP_URL=wss://api.try.direct/mcp
REACT_APP_API_URL=https://api.try.direct
REACT_APP_OPENAI_API_KEY=your_openai_key_here
```

### Development Setup

```bash
# .env.development
REACT_APP_MCP_URL=ws://localhost:8000/mcp
REACT_APP_API_URL=http://localhost:8000
REACT_APP_OPENAI_API_KEY=your_openai_key_here
```

---

## Error Handling Best Practices

```typescript
// src/lib/mcp/errorHandler.ts

export class McpError extends Error {
  constructor(
    message: string,
    public code: string,
    public recoverable: boolean = true
  ) {
    super(message);
    this.name = 'McpError';
  }
}

export const handleMcpError = (error: unknown): McpError => {
  if (error instanceof McpError) {
    return error;
  }
  
  if (error instanceof Error) {
    if (error.message.includes('WebSocket')) {
      return new McpError(
        'Connection lost. Please refresh the page.',
        'CONNECTION_LOST',
        true
      );
    }
    
    if (error.message.includes('auth')) {
      return new McpError(
        'Authentication failed. Please log in again.',
        'AUTH_FAILED',
        false
      );
    }
  }
  
  return new McpError(
    'An unexpected error occurred.',
    'UNKNOWN_ERROR',
    true
  );
};
```

---

## Deployment Checklist

### Pre-Launch
- [ ] All MCP tools tested and working
- [ ] WebSocket connection stable for extended periods
- [ ] Error handling covers all edge cases
- [ ] Loading states implemented for all async operations
- [ ] Mobile responsive design verified
- [ ] Authentication integrated with existing OAuth
- [ ] Rate limiting enforced on frontend
- [ ] CORS configured for production domain

### Production
- [ ] Environment variables set correctly
- [ ] HTTPS/WSS enabled for secure connections
- [ ] CDN configured for static assets
- [ ] Analytics tracking added
- [ ] Error logging (Sentry, LogRocket)
- [ ] Performance monitoring
- [ ] User feedback mechanism

---

## User Flows & Examples

### Example 1: Create WordPress Site

**User**: "Create a WordPress site"

**AI Response**: "I'll help you create a WordPress site. Let me ask a few questions:
1. What would you like to name your project?
2. Do you need a database (MySQL)?
3. Expected traffic level (low/medium/high)?"

**User**: "Call it 'My Blog', yes I need MySQL, low traffic"

**AI**: *Calls tools:*
```
suggest_resources({ app_type: "wordpress", expected_traffic: "low" })
suggest_resources({ app_type: "mysql", expected_traffic: "low" })
create_project({
  name: "My Blog",
  apps: [
    { name: "wordpress", dockerImage: { repository: "wordpress" }, resources: { cpu: 1, ram: 2, storage: 20 } },
    { name: "mysql", dockerImage: { repository: "mysql" }, resources: { cpu: 2, ram: 4, storage: 50 } }
  ]
})
```

**AI Response**: "✓ Created project 'My Blog' with WordPress and MySQL! Resource suggestions:
- WordPress: 1 CPU, 2GB RAM, 20GB storage
- MySQL: 2 CPU, 4GB RAM, 50GB storage

Would you like to deploy this now?"

### Example 2: List Projects

**User**: "Show my projects"

**AI**: *Calls `list_projects()`*

**AI Response**: "You have 3 projects:
1. My Blog (WordPress + MySQL) - Created Dec 27
2. API Server (Node.js) - Created Dec 26
3. E-commerce (Next.js + PostgreSQL) - Created Dec 25

Which one would you like to work on?"

---

## Troubleshooting Guide

### Common Issues

#### 1. WebSocket Connection Fails
```typescript
// Check: Is MCP server running?
// Check: Is auth token valid?
// Check: CORS headers configured?

// Solution:
console.log('MCP URL:', process.env.REACT_APP_MCP_URL);
console.log('Auth token:', token ? 'Present' : 'Missing');
```

#### 2. Tool Calls Timeout
```typescript
// Increase timeout in client
const result = await client.callTool(name, args, { timeout: 30000 });
```

#### 3. Context Not Persisting
```typescript
// Check: Is Zustand store properly configured?
// Ensure setContext is called after tool execution
useChatStore.getState().setContext({ currentProject: project });
```

---

## Future Enhancements

### Phase 2 Features
- **Voice Input**: Add speech-to-text for hands-free interaction
- **Template Marketplace**: Browse and install community templates
- **Multi-language Support**: Internationalization for non-English users
- **Collaborative Editing**: Multiple users working on same project
- **Version Control**: Git integration for project configurations
- **Cost Estimation**: Show estimated monthly costs for deployments

### Advanced AI Features
- **Proactive Suggestions**: AI monitors form and suggests improvements
- **Error Prevention**: Validate before deployment and warn about issues
- **Learning Mode**: AI learns from user preferences over time
- **Guided Tutorials**: Step-by-step walkthroughs for beginners

---

## Performance Targets

- **Initial Load**: < 2 seconds
- **Chat Message Latency**: < 500ms
- **Tool Execution**: < 3 seconds (p95)
- **WebSocket Reconnect**: < 5 seconds
- **Memory Usage**: < 50MB per tab

---

## Security Considerations

1. **Token Security**: Never expose OpenAI API key in frontend; use backend proxy
2. **Input Sanitization**: Validate all user inputs before sending to AI
3. **Rate Limiting**: Implement frontend rate limiting to prevent abuse
4. **XSS Prevention**: Sanitize AI responses before rendering as HTML
5. **CSP Headers**: Configure Content Security Policy for production

---

## Team Coordination

### Frontend Team Responsibilities
- Implement React components
- Design chat UI/UX
- Handle state management
- Write unit/integration tests

### Backend Team Responsibilities
- Ensure MCP server is production-ready
- Provide WebSocket endpoint
- Maintain tool schemas
- Monitor performance

### Shared Responsibilities
- Define tool contracts (JSON schemas)
- End-to-end testing
- Documentation
- Deployment coordination

---

## Resources & Links

- **MCP SDK Docs**: https://github.com/modelcontextprotocol/sdk
- **OpenAI API**: https://platform.openai.com/docs
- **WebSocket API**: https://developer.mozilla.org/en-US/docs/Web/API/WebSocket
- **React Query**: https://tanstack.com/query/latest
- **Zustand**: https://github.com/pmndrs/zustand

---

## Contact

**Frontend Lead**: [Your Name]
**Questions**: Open GitHub issue or Slack #stacker-ai channel
