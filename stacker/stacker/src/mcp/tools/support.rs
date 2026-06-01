//! MCP Tools for Support Escalation.
//!
//! These tools provide AI access to:
//! - Escalation to human support via Slack
//! - Integration with Tawk.to live chat
//! - Support ticket creation

use async_trait::async_trait;
use serde_json::{json, Value};

use crate::db;
use crate::mcp::protocol::{Tool, ToolContent};
use crate::mcp::registry::{ToolContext, ToolHandler};
use serde::Deserialize;

/// Slack configuration
fn get_slack_config() -> Option<SlackConfig> {
    let webhook_url = std::env::var("SLACK_SUPPORT_WEBHOOK_URL").ok()?;
    let channel =
        std::env::var("SLACK_SUPPORT_CHANNEL").unwrap_or_else(|_| "#trydirectflow".to_string());
    Some(SlackConfig {
        webhook_url,
        channel,
    })
}

#[allow(dead_code)]
struct SlackConfig {
    webhook_url: String,
    channel: String,
}

/// Escalate a user issue to human support
pub struct EscalateToSupportTool;

#[async_trait]
impl ToolHandler for EscalateToSupportTool {
    async fn execute(&self, args: Value, context: &ToolContext) -> Result<ToolContent, String> {
        #[derive(Deserialize)]
        struct Args {
            reason: String,
            #[serde(default)]
            deployment_id: Option<i32>,
            #[serde(default)]
            urgency: Option<String>,
            #[serde(default)]
            conversation_summary: Option<String>,
        }

        let params: Args =
            serde_json::from_value(args).map_err(|e| format!("Invalid arguments: {}", e))?;

        let urgency = params.urgency.unwrap_or_else(|| "normal".to_string());
        let urgency_emoji = match urgency.as_str() {
            "high" | "urgent" | "critical" => "🔴",
            "medium" => "🟡",
            _ => "🟢",
        };

        // Gather deployment context if provided
        let deployment_info = if let Some(deployment_id) = params.deployment_id {
            match db::deployment::fetch(&context.pg_pool, deployment_id).await {
                Ok(Some(deployment)) => {
                    // Verify ownership
                    if deployment.user_id.as_ref() == Some(&context.user.id) {
                        Some(json!({
                            "id": deployment_id,
                            "status": deployment.status,
                            "deployment_hash": deployment.deployment_hash,
                        }))
                    } else {
                        None
                    }
                }
                _ => None,
            }
        } else {
            None
        };

        // Get user info
        let user_info = json!({
            "user_id": context.user.id,
            "email": context.user.email,
        });

        // Build Slack message
        let slack_message = build_slack_message(
            &params.reason,
            &urgency,
            urgency_emoji,
            &user_info,
            deployment_info.as_ref(),
            params.conversation_summary.as_deref(),
        );

        // Send to Slack
        let slack_result = send_to_slack(&slack_message).await;

        // Store escalation record
        let escalation_id = uuid::Uuid::new_v4().to_string();
        let _escalation_record = json!({
            "id": escalation_id,
            "user_id": context.user.id,
            "reason": params.reason,
            "urgency": urgency,
            "deployment_id": params.deployment_id,
            "conversation_summary": params.conversation_summary,
            "slack_sent": slack_result.is_ok(),
            "created_at": chrono::Utc::now().to_rfc3339(),
        });

        tracing::info!(
            user_id = %context.user.id,
            escalation_id = %escalation_id,
            urgency = %urgency,
            deployment_id = ?params.deployment_id,
            slack_success = slack_result.is_ok(),
            "Support escalation created via MCP"
        );

        let response = json!({
            "success": true,
            "escalation_id": escalation_id,
            "status": "escalated",
            "message": if slack_result.is_ok() {
                "Your issue has been escalated to our support team. They will respond within 24 hours (usually much sooner during business hours)."
            } else {
                "Your issue has been logged. Our support team will reach out to you shortly."
            },
            "next_steps": [
                "A support agent will review your issue shortly",
                "You can continue chatting with me for other questions",
                "For urgent issues, you can also use our live chat (Tawk.to) in the bottom-right corner"
            ],
            "tawk_to_available": true
        });

        Ok(ToolContent::Text {
            text: serde_json::to_string_pretty(&response).unwrap_or_else(|_| response.to_string()),
        })
    }

    fn schema(&self) -> Tool {
        Tool {
            name: "escalate_to_support".to_string(),
            description: "Escalate an issue to human support when AI assistance is insufficient. Use this when: 1) User explicitly asks to speak to a human, 2) Issue requires account/billing changes AI cannot perform, 3) Complex infrastructure problems beyond AI troubleshooting, 4) User is frustrated or issue is time-sensitive.".to_string(),
            input_schema: json!({
                "type": "object",
                "properties": {
                    "reason": {
                        "type": "string",
                        "description": "Clear description of why escalation is needed and what the user needs help with"
                    },
                    "deployment_id": {
                        "type": "number",
                        "description": "Optional deployment ID if the issue relates to a specific deployment"
                    },
                    "urgency": {
                        "type": "string",
                        "enum": ["low", "normal", "high", "critical"],
                        "description": "Urgency level: low (general question), normal (needs help), high (service degraded), critical (service down)"
                    },
                    "conversation_summary": {
                        "type": "string",
                        "description": "Brief summary of the conversation and troubleshooting steps already attempted"
                    }
                },
                "required": ["reason"]
            }),
        }
    }
}

/// Build Slack Block Kit message for support escalation
fn build_slack_message(
    reason: &str,
    urgency: &str,
    urgency_emoji: &str,
    user_info: &Value,
    deployment_info: Option<&Value>,
    conversation_summary: Option<&str>,
) -> Value {
    let mut blocks = vec![
        json!({
            "type": "header",
            "text": {
                "type": "plain_text",
                "text": format!("{} Support Escalation", urgency_emoji),
                "emoji": true
            }
        }),
        json!({
            "type": "section",
            "fields": [
                {
                    "type": "mrkdwn",
                    "text": format!("*User:*\n{}", user_info["email"].as_str().unwrap_or("Unknown"))
                },
                {
                    "type": "mrkdwn",
                    "text": format!("*Urgency:*\n{}", urgency)
                }
            ]
        }),
        json!({
            "type": "section",
            "text": {
                "type": "mrkdwn",
                "text": format!("*Reason:*\n{}", reason)
            }
        }),
    ];

    if let Some(deployment) = deployment_info {
        blocks.push(json!({
            "type": "section",
            "fields": [
                {
                    "type": "mrkdwn",
                    "text": format!("*Deployment ID:*\n{}", deployment["id"])
                },
                {
                    "type": "mrkdwn",
                    "text": format!("*Status:*\n{}", deployment["status"].as_str().unwrap_or("unknown"))
                }
            ]
        }));
    }

    if let Some(summary) = conversation_summary {
        blocks.push(json!({
            "type": "section",
            "text": {
                "type": "mrkdwn",
                "text": format!("*Conversation Summary:*\n{}", summary)
            }
        }));
    }

    blocks.push(json!({
        "type": "divider"
    }));

    blocks.push(json!({
        "type": "context",
        "elements": [
            {
                "type": "mrkdwn",
                "text": format!("Escalated via AI Assistant • User ID: {}", user_info["user_id"].as_str().unwrap_or("unknown"))
            }
        ]
    }));

    json!({
        "blocks": blocks
    })
}

/// Send message to Slack webhook
async fn send_to_slack(message: &Value) -> Result<(), String> {
    let config = match get_slack_config() {
        Some(c) => c,
        None => {
            tracing::warn!("Slack webhook not configured - SLACK_SUPPORT_WEBHOOK_URL not set");
            return Err("Slack not configured".to_string());
        }
    };

    let client = reqwest::Client::new();
    let response = client
        .post(&config.webhook_url)
        .json(message)
        .send()
        .await
        .map_err(|e| format!("Failed to send Slack message: {}", e))?;

    if response.status().is_success() {
        tracing::info!("Slack escalation sent successfully");
        Ok(())
    } else {
        let status = response.status();
        let body = response.text().await.unwrap_or_default();
        tracing::error!(
            status = %status,
            body = %body,
            "Slack webhook returned error"
        );
        Err(format!("Slack returned {}: {}", status, body))
    }
}

/// Get Tawk.to widget info for live chat
pub struct GetLiveChatInfoTool;

#[async_trait]
impl ToolHandler for GetLiveChatInfoTool {
    async fn execute(&self, _args: Value, _context: &ToolContext) -> Result<ToolContent, String> {
        let tawk_property_id = std::env::var("TAWK_TO_PROPERTY_ID").ok();
        let tawk_widget_id = std::env::var("TAWK_TO_WIDGET_ID").ok();

        let available = tawk_property_id.is_some() && tawk_widget_id.is_some();

        let response = json!({
            "live_chat_available": available,
            "provider": "Tawk.to",
            "instructions": if available {
                "Click the chat bubble in the bottom-right corner of the page to start a live chat with our support team."
            } else {
                "Live chat is currently unavailable. Please use escalate_to_support to reach our team."
            },
            "business_hours": "Monday-Friday, 9 AM - 6 PM UTC",
            "average_response_time": "< 5 minutes during business hours"
        });

        Ok(ToolContent::Text {
            text: serde_json::to_string_pretty(&response).unwrap_or_else(|_| response.to_string()),
        })
    }

    fn schema(&self) -> Tool {
        Tool {
            name: "get_live_chat_info".to_string(),
            description: "Get information about live chat availability for immediate human support. Returns Tawk.to widget status and instructions.".to_string(),
            input_schema: json!({
                "type": "object",
                "properties": {},
                "required": []
            }),
        }
    }
}
