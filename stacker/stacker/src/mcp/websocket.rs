use crate::configuration::Settings;
use crate::models;
use actix::{Actor, ActorContext, AsyncContext, StreamHandler};
use actix_casbin_auth::CasbinService;
use actix_web::{web, Error, HttpRequest, HttpResponse};
use actix_web_actors::ws;
use sqlx::PgPool;
use std::sync::Arc;
use std::time::{Duration, Instant};

use super::protocol::{
    CallToolRequest, CallToolResponse, InitializeParams, InitializeResult, JsonRpcError,
    JsonRpcRequest, JsonRpcResponse, ServerCapabilities, ServerInfo, ToolListResponse,
    ToolsCapability,
};
use super::registry::{ToolContext, ToolRegistry};
use super::session::McpSession;
use crate::services::TypedErrorEnvelope;

/// WebSocket heartbeat interval
const HEARTBEAT_INTERVAL: Duration = Duration::from_secs(5);
/// Client timeout - close connection if no heartbeat received
const CLIENT_TIMEOUT: Duration = Duration::from_secs(10);

/// MCP WebSocket actor
pub struct McpWebSocket {
    user: Arc<models::User>,
    session: McpSession,
    registry: Arc<ToolRegistry>,
    pg_pool: PgPool,
    settings: web::Data<Settings>,
    casbin_service: CasbinService,
    hb: Instant,
}

impl McpWebSocket {
    pub fn new(
        user: Arc<models::User>,
        registry: Arc<ToolRegistry>,
        pg_pool: PgPool,
        settings: web::Data<Settings>,
        casbin_service: CasbinService,
    ) -> Self {
        Self {
            user,
            session: McpSession::new(),
            registry,
            pg_pool,
            settings,
            casbin_service,
            hb: Instant::now(),
        }
    }

    /// Start heartbeat process to check connection health
    fn hb(&self, ctx: &mut <Self as Actor>::Context) {
        ctx.run_interval(HEARTBEAT_INTERVAL, |act, ctx| {
            if Instant::now().duration_since(act.hb) > CLIENT_TIMEOUT {
                tracing::warn!("MCP WebSocket client heartbeat failed, disconnecting");
                ctx.stop();
                return;
            }

            ctx.ping(b"");
        });
    }

    /// Handle JSON-RPC request
    async fn handle_jsonrpc(&self, req: JsonRpcRequest) -> Option<JsonRpcResponse> {
        // Notifications arrive without an id and must not receive a response per JSON-RPC 2.0
        if req.id.is_none() {
            if req.method == "notifications/initialized" {
                tracing::info!("Ignoring notifications/initialized (notification)");
            } else {
                tracing::warn!("Ignoring notification without id: method={}", req.method);
            }
            return None;
        }

        let response = match req.method.as_str() {
            "initialize" => self.handle_initialize(req).await,
            "tools/list" => self.handle_tools_list(req).await,
            "tools/call" => self.handle_tools_call(req).await,
            _ => JsonRpcResponse::error(req.id, JsonRpcError::method_not_found(&req.method)),
        };

        Some(response)
    }

    /// Handle MCP initialize method
    async fn handle_initialize(&self, req: JsonRpcRequest) -> JsonRpcResponse {
        let params: InitializeParams = match req.params {
            Some(p) => match serde_json::from_value(p) {
                Ok(params) => params,
                Err(e) => {
                    return JsonRpcResponse::error(
                        req.id,
                        JsonRpcError::invalid_params(&e.to_string()),
                    )
                }
            },
            None => {
                return JsonRpcResponse::error(
                    req.id,
                    JsonRpcError::invalid_params("Missing params"),
                )
            }
        };

        tracing::info!(
            "MCP client initialized: protocol_version={}, client={}",
            params.protocol_version,
            params
                .client_info
                .as_ref()
                .map(|c| c.name.as_str())
                .unwrap_or("unknown")
        );

        let result = InitializeResult {
            protocol_version: "2024-11-05".to_string(),
            capabilities: ServerCapabilities {
                tools: Some(ToolsCapability {
                    list_changed: Some(false),
                }),
                experimental: None,
            },
            server_info: ServerInfo {
                name: "stacker-mcp".to_string(),
                version: env!("CARGO_PKG_VERSION").to_string(),
            },
        };

        JsonRpcResponse::success(req.id, serde_json::to_value(result).unwrap())
    }

    /// Handle tools/list method
    async fn handle_tools_list(&self, req: JsonRpcRequest) -> JsonRpcResponse {
        let tools = self.registry.list_tools();

        tracing::debug!("Listing {} available tools", tools.len());

        let result = ToolListResponse { tools };

        JsonRpcResponse::success(req.id, serde_json::to_value(result).unwrap())
    }

    /// Handle tools/call method
    async fn handle_tools_call(&self, req: JsonRpcRequest) -> JsonRpcResponse {
        let call_req: CallToolRequest = match req.params {
            Some(p) => match serde_json::from_value(p) {
                Ok(params) => params,
                Err(e) => {
                    return JsonRpcResponse::error(
                        req.id,
                        JsonRpcError::invalid_params(&e.to_string()),
                    )
                }
            },
            None => {
                return JsonRpcResponse::error(
                    req.id,
                    JsonRpcError::invalid_params("Missing params"),
                )
            }
        };

        let tool_span = tracing::info_span!(
            "mcp_tool_call",
            tool = %call_req.name,
            user = %self.user.id
        );
        let _enter = tool_span.enter();

        match self.registry.get(&call_req.name) {
            Some(handler) => {
                if let Err(err) = self
                    .registry
                    .authorize_call(&call_req.name, &self.user, self.casbin_service.clone())
                    .await
                {
                    tracing::warn!(tool = %call_req.name, error = %err, "MCP tool authorization failed");
                    let response = CallToolResponse::typed_error(
                        TypedErrorEnvelope::from_mcp_error_message(&err),
                    );
                    return JsonRpcResponse::success(
                        req.id,
                        serde_json::to_value(response).unwrap(),
                    );
                }

                let context = ToolContext {
                    user: self.user.clone(),
                    pg_pool: self.pg_pool.clone(),
                    settings: self.settings.clone(),
                };

                match handler
                    .execute(
                        call_req.arguments.unwrap_or(serde_json::json!({})),
                        &context,
                    )
                    .await
                {
                    Ok(content) => {
                        tracing::info!("Tool executed successfully");
                        let response = CallToolResponse {
                            content: vec![content],
                            is_error: None,
                        };
                        JsonRpcResponse::success(req.id, serde_json::to_value(response).unwrap())
                    }
                    Err(e) => {
                        tracing::error!("Tool execution failed: {}", e);
                        let response = CallToolResponse::typed_error(
                            TypedErrorEnvelope::from_mcp_error_message(&e),
                        );
                        JsonRpcResponse::success(req.id, serde_json::to_value(response).unwrap())
                    }
                }
            }
            None => {
                tracing::warn!("Tool not found: {}", call_req.name);
                JsonRpcResponse::error(
                    req.id,
                    JsonRpcError::custom(
                        -32001,
                        format!("Tool not found: {}", call_req.name),
                        None,
                    ),
                )
            }
        }
    }
}

impl Actor for McpWebSocket {
    type Context = ws::WebsocketContext<Self>;

    fn started(&mut self, ctx: &mut Self::Context) {
        tracing::info!(
            "MCP WebSocket connection started: session_id={}, user={}",
            self.session.id,
            self.user.id
        );
        self.hb(ctx);
    }

    fn stopped(&mut self, _ctx: &mut Self::Context) {
        tracing::info!(
            "MCP WebSocket connection closed: session_id={}, user={}",
            self.session.id,
            self.user.id
        );
    }
}

impl StreamHandler<Result<ws::Message, ws::ProtocolError>> for McpWebSocket {
    fn handle(&mut self, msg: Result<ws::Message, ws::ProtocolError>, ctx: &mut Self::Context) {
        match msg {
            Ok(ws::Message::Ping(msg)) => {
                self.hb = Instant::now();
                ctx.pong(&msg);
            }
            Ok(ws::Message::Pong(_)) => {
                self.hb = Instant::now();
            }
            Ok(ws::Message::Text(text)) => {
                tracing::info!("[MCP] Received JSON-RPC message: {}", text);

                let request: JsonRpcRequest = match serde_json::from_str(&text) {
                    Ok(req) => req,
                    Err(e) => {
                        tracing::error!("[MCP] Failed to parse JSON-RPC request: {}", e);
                        let error_response =
                            JsonRpcResponse::error(None, JsonRpcError::parse_error());
                        let response_text = serde_json::to_string(&error_response).unwrap();
                        tracing::error!("[MCP] Sending parse error response: {}", response_text);
                        ctx.text(response_text);
                        return;
                    }
                };

                let user = self.user.clone();
                let session = self.session.clone();
                let registry = self.registry.clone();
                let pg_pool = self.pg_pool.clone();
                let settings = self.settings.clone();
                let casbin_service = self.casbin_service.clone();

                let fut = async move {
                    let ws = McpWebSocket {
                        user,
                        session,
                        registry,
                        pg_pool,
                        settings,
                        casbin_service,
                        hb: Instant::now(),
                    };
                    ws.handle_jsonrpc(request).await
                };

                let addr = ctx.address();
                actix::spawn(async move {
                    if let Some(response) = fut.await {
                        addr.do_send(SendResponse(response));
                    } else {
                        tracing::debug!("[MCP] Dropped response for notification (no id)");
                    }
                });
            }
            Ok(ws::Message::Binary(_)) => {
                tracing::warn!("Binary messages not supported in MCP protocol");
            }
            Ok(ws::Message::Close(reason)) => {
                tracing::info!("MCP WebSocket close received: {:?}", reason);
                ctx.close(reason);
                ctx.stop();
            }
            _ => {}
        }
    }
}

/// Message to send JSON-RPC response back to client
#[derive(actix::Message)]
#[rtype(result = "()")]
struct SendResponse(JsonRpcResponse);

impl actix::Handler<SendResponse> for McpWebSocket {
    type Result = ();

    fn handle(&mut self, msg: SendResponse, ctx: &mut Self::Context) {
        let response_text = serde_json::to_string(&msg.0).unwrap();
        tracing::info!(
            "[MCP] Sending JSON-RPC response: id={:?}, has_result={}, has_error={}, message={}",
            msg.0.id,
            msg.0.result.is_some(),
            msg.0.error.is_some(),
            response_text
        );
        ctx.text(response_text);
    }
}

/// WebSocket route handler - entry point for MCP connections
#[tracing::instrument(
    name = "MCP WebSocket connection",
    skip(req, stream, user, registry, pg_pool, settings, casbin_service)
)]
pub async fn mcp_websocket(
    req: HttpRequest,
    stream: web::Payload,
    user: web::ReqData<Arc<models::User>>,
    registry: web::Data<Arc<ToolRegistry>>,
    pg_pool: web::Data<PgPool>,
    settings: web::Data<Settings>,
    casbin_service: web::Data<CasbinService>,
) -> Result<HttpResponse, Error> {
    tracing::info!(
        "New MCP WebSocket connection request from user: {}",
        user.id
    );

    let ws = McpWebSocket::new(
        user.into_inner(),
        registry.get_ref().clone(),
        pg_pool.get_ref().clone(),
        settings.clone(),
        casbin_service.get_ref().clone(),
    );

    // The MCP SDK requests subprotocol "mcp" via Sec-WebSocket-Protocol header.
    // Chrome strictly enforces subprotocol negotiation and will reject the
    // connection if the server does not echo the requested protocol back.
    // Firefox is more lenient, which is why it works there but not in Chrome.
    ws::WsResponseBuilder::new(ws, &req, stream)
        .protocols(&["mcp"])
        .start()
}
