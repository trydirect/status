use async_trait::async_trait;
use serde_json::{json, Value};

use crate::db;
use crate::helpers::security_validator;
use crate::mcp::protocol::{Tool, ToolContent};
use crate::mcp::registry::{ToolContext, ToolHandler};
use serde::Deserialize;

fn require_admin(context: &ToolContext) -> Result<(), String> {
    let role = context.user.role.as_str();
    if role != "admin_service" && role != "group_admin" && role != "root" {
        return Err("Access denied: admin role required".to_string());
    }
    Ok(())
}

/// List submitted marketplace templates awaiting admin review
pub struct AdminListSubmittedTemplatesTool;

#[async_trait]
impl ToolHandler for AdminListSubmittedTemplatesTool {
    async fn execute(&self, _args: Value, context: &ToolContext) -> Result<ToolContent, String> {
        require_admin(context)?;

        let templates = db::marketplace::admin_list_submitted(&context.pg_pool)
            .await
            .map_err(|e| format!("Database error: {}", e))?;

        let result = json!({
            "count": templates.len(),
            "templates": templates,
        });

        tracing::info!("Admin listed {} submitted templates", templates.len());

        Ok(ToolContent::Text {
            text: serde_json::to_string(&result).unwrap(),
        })
    }

    fn schema(&self) -> Tool {
        Tool {
            name: "admin_list_submitted_templates".to_string(),
            description: "List marketplace templates submitted for review. Returns templates with status 'submitted' awaiting admin approval or rejection.".to_string(),
            input_schema: json!({
                "type": "object",
                "properties": {},
                "required": []
            }),
        }
    }
}

/// Get detailed information about a specific marketplace template including versions and reviews
pub struct AdminGetTemplateDetailTool;

#[async_trait]
impl ToolHandler for AdminGetTemplateDetailTool {
    async fn execute(&self, args: Value, context: &ToolContext) -> Result<ToolContent, String> {
        require_admin(context)?;

        #[derive(Deserialize)]
        struct Args {
            template_id: String,
        }

        let params: Args =
            serde_json::from_value(args).map_err(|e| format!("Invalid arguments: {}", e))?;

        let id = uuid::Uuid::parse_str(&params.template_id)
            .map_err(|_| "Invalid UUID format for template_id".to_string())?;

        let template = db::marketplace::get_by_id(&context.pg_pool, id)
            .await
            .map_err(|e| format!("Database error: {}", e))?
            .ok_or_else(|| "Template not found".to_string())?;

        let versions = db::marketplace::list_versions_by_template(&context.pg_pool, id)
            .await
            .map_err(|e| format!("Database error fetching versions: {}", e))?;

        let reviews = db::marketplace::list_reviews_by_template(&context.pg_pool, id)
            .await
            .map_err(|e| format!("Database error fetching reviews: {}", e))?;

        let result = json!({
            "template": template,
            "versions": versions,
            "reviews": reviews,
        });

        tracing::info!(
            "Admin fetched detail for template {} ({} versions, {} reviews)",
            id,
            versions.len(),
            reviews.len()
        );

        Ok(ToolContent::Text {
            text: serde_json::to_string(&result).unwrap(),
        })
    }

    fn schema(&self) -> Tool {
        Tool {
            name: "admin_get_template_detail".to_string(),
            description: "Get full details of a marketplace template including all versions (with stack_definition, changelog) and review history (decisions, reasons, security checklist).".to_string(),
            input_schema: json!({
                "type": "object",
                "properties": {
                    "template_id": {
                        "type": "string",
                        "description": "UUID of the template to inspect"
                    }
                },
                "required": ["template_id"]
            }),
        }
    }
}

/// Approve a submitted marketplace template
pub struct AdminApproveTemplateTool;

#[async_trait]
impl ToolHandler for AdminApproveTemplateTool {
    async fn execute(&self, args: Value, context: &ToolContext) -> Result<ToolContent, String> {
        require_admin(context)?;

        #[derive(Deserialize)]
        struct Args {
            template_id: String,
            #[serde(default)]
            reason: Option<String>,
        }

        let params: Args =
            serde_json::from_value(args).map_err(|e| format!("Invalid arguments: {}", e))?;

        let id = uuid::Uuid::parse_str(&params.template_id)
            .map_err(|_| "Invalid UUID format for template_id".to_string())?;

        let updated = db::marketplace::admin_decide(
            &context.pg_pool,
            &id,
            &context.user.id,
            "approved",
            params.reason.as_deref(),
            None,
        )
        .await
        .map_err(|e| format!("Database error: {}", e))?;

        if !updated {
            return Err("Template not found or not in a reviewable state".to_string());
        }

        tracing::info!("Admin {} approved template {}", context.user.id, id);

        let result = json!({
            "template_id": params.template_id,
            "decision": "approved",
            "message": "Template has been approved. A product record will be auto-created by database trigger.",
        });

        Ok(ToolContent::Text {
            text: serde_json::to_string(&result).unwrap(),
        })
    }

    fn schema(&self) -> Tool {
        Tool {
            name: "admin_approve_template".to_string(),
            description: "Approve a submitted marketplace template. This changes the template status to 'approved' and triggers automatic product creation.".to_string(),
            input_schema: json!({
                "type": "object",
                "properties": {
                    "template_id": {
                        "type": "string",
                        "description": "UUID of the template to approve"
                    },
                    "reason": {
                        "type": "string",
                        "description": "Optional approval note/comment"
                    }
                },
                "required": ["template_id"]
            }),
        }
    }
}

/// Reject a submitted marketplace template
pub struct AdminRejectTemplateTool;

#[async_trait]
impl ToolHandler for AdminRejectTemplateTool {
    async fn execute(&self, args: Value, context: &ToolContext) -> Result<ToolContent, String> {
        require_admin(context)?;

        #[derive(Deserialize)]
        struct Args {
            template_id: String,
            reason: String,
        }

        let params: Args =
            serde_json::from_value(args).map_err(|e| format!("Invalid arguments: {}", e))?;

        let id = uuid::Uuid::parse_str(&params.template_id)
            .map_err(|_| "Invalid UUID format for template_id".to_string())?;

        let updated = db::marketplace::admin_decide(
            &context.pg_pool,
            &id,
            &context.user.id,
            "rejected",
            Some(&params.reason),
            None,
        )
        .await
        .map_err(|e| format!("Database error: {}", e))?;

        if !updated {
            return Err("Template not found or not in a reviewable state".to_string());
        }

        tracing::info!(
            "Admin {} rejected template {} (reason: {})",
            context.user.id,
            id,
            params.reason
        );

        let result = json!({
            "template_id": params.template_id,
            "decision": "rejected",
            "reason": params.reason,
            "message": "Template has been rejected. The creator will be notified.",
        });

        Ok(ToolContent::Text {
            text: serde_json::to_string(&result).unwrap(),
        })
    }

    fn schema(&self) -> Tool {
        Tool {
            name: "admin_reject_template".to_string(),
            description: "Reject a submitted marketplace template with a reason. The template creator will be notified of the rejection.".to_string(),
            input_schema: json!({
                "type": "object",
                "properties": {
                    "template_id": {
                        "type": "string",
                        "description": "UUID of the template to reject"
                    },
                    "reason": {
                        "type": "string",
                        "description": "Reason for rejection (required, shown to template creator)"
                    }
                },
                "required": ["template_id", "reason"]
            }),
        }
    }
}

/// List all versions of a specific marketplace template
pub struct AdminListTemplateVersionsTool;

#[async_trait]
impl ToolHandler for AdminListTemplateVersionsTool {
    async fn execute(&self, args: Value, context: &ToolContext) -> Result<ToolContent, String> {
        require_admin(context)?;

        #[derive(Deserialize)]
        struct Args {
            template_id: String,
        }

        let params: Args =
            serde_json::from_value(args).map_err(|e| format!("Invalid arguments: {}", e))?;

        let id = uuid::Uuid::parse_str(&params.template_id)
            .map_err(|_| "Invalid UUID format for template_id".to_string())?;

        let versions = db::marketplace::list_versions_by_template(&context.pg_pool, id)
            .await
            .map_err(|e| format!("Database error: {}", e))?;

        let result = json!({
            "template_id": params.template_id,
            "count": versions.len(),
            "versions": versions,
        });

        tracing::info!(
            "Admin listed {} versions for template {}",
            versions.len(),
            id
        );

        Ok(ToolContent::Text {
            text: serde_json::to_string(&result).unwrap(),
        })
    }

    fn schema(&self) -> Tool {
        Tool {
            name: "admin_list_template_versions".to_string(),
            description: "List all versions of a marketplace template including stack_definition, changelog, and version metadata.".to_string(),
            input_schema: json!({
                "type": "object",
                "properties": {
                    "template_id": {
                        "type": "string",
                        "description": "UUID of the template"
                    }
                },
                "required": ["template_id"]
            }),
        }
    }
}

/// List review history for a marketplace template
pub struct AdminListTemplateReviewsTool;

#[async_trait]
impl ToolHandler for AdminListTemplateReviewsTool {
    async fn execute(&self, args: Value, context: &ToolContext) -> Result<ToolContent, String> {
        require_admin(context)?;

        #[derive(Deserialize)]
        struct Args {
            template_id: String,
        }

        let params: Args =
            serde_json::from_value(args).map_err(|e| format!("Invalid arguments: {}", e))?;

        let id = uuid::Uuid::parse_str(&params.template_id)
            .map_err(|_| "Invalid UUID format for template_id".to_string())?;

        let reviews = db::marketplace::list_reviews_by_template(&context.pg_pool, id)
            .await
            .map_err(|e| format!("Database error: {}", e))?;

        let result = json!({
            "template_id": params.template_id,
            "count": reviews.len(),
            "reviews": reviews,
        });

        tracing::info!("Admin listed {} reviews for template {}", reviews.len(), id);

        Ok(ToolContent::Text {
            text: serde_json::to_string(&result).unwrap(),
        })
    }

    fn schema(&self) -> Tool {
        Tool {
            name: "admin_list_template_reviews".to_string(),
            description: "List the review history of a marketplace template including past decisions, reasons, reviewer info, and security checklist results.".to_string(),
            input_schema: json!({
                "type": "object",
                "properties": {
                    "template_id": {
                        "type": "string",
                        "description": "UUID of the template"
                    }
                },
                "required": ["template_id"]
            }),
        }
    }
}

/// Run automated security validation on a marketplace template's stack definition.
/// Returns the full security report AND the raw stack_definition for AI to perform
/// deeper analysis beyond what automated rules can catch.
pub struct AdminValidateTemplateSecurityTool;

#[async_trait]
impl ToolHandler for AdminValidateTemplateSecurityTool {
    async fn execute(&self, args: Value, context: &ToolContext) -> Result<ToolContent, String> {
        require_admin(context)?;

        #[derive(Deserialize)]
        struct Args {
            template_id: String,
            /// If true, save the scan result as a review record
            #[serde(default)]
            save_report: Option<bool>,
        }

        let params: Args =
            serde_json::from_value(args).map_err(|e| format!("Invalid arguments: {}", e))?;

        let id = uuid::Uuid::parse_str(&params.template_id)
            .map_err(|_| "Invalid UUID format for template_id".to_string())?;

        // Fetch template
        let template = db::marketplace::get_by_id(&context.pg_pool, id)
            .await
            .map_err(|e| format!("Database error: {}", e))?
            .ok_or_else(|| "Template not found".to_string())?;

        // Fetch latest version with stack_definition
        let versions = db::marketplace::list_versions_by_template(&context.pg_pool, id)
            .await
            .map_err(|e| format!("Database error: {}", e))?;

        let latest = versions
            .iter()
            .find(|v| v.is_latest == Some(true))
            .or_else(|| versions.first())
            .ok_or_else(|| "No versions found for this template — nothing to scan".to_string())?;

        // Run automated security checks
        let report = security_validator::validate_stack_security(&latest.stack_definition);

        // Optionally save the scan result as a review record
        let saved_review = if params.save_report.unwrap_or(true) {
            let review = db::marketplace::save_security_scan(
                &context.pg_pool,
                &id,
                &context.user.id,
                report.to_checklist_json(),
            )
            .await
            .map_err(|e| format!("Failed to save security report: {}", e))?;
            Some(review.id.to_string())
        } else {
            None
        };

        tracing::info!(
            "Security scan for template {}: overall_passed={}, risk_score={}",
            id,
            report.overall_passed,
            report.risk_score
        );

        // Return both the automated report AND the raw stack_definition
        // so the AI agent can perform deeper semantic analysis
        let result = json!({
            "template": {
                "id": template.id,
                "name": template.name,
                "status": template.status,
                "creator_name": template.creator_name,
            },
            "version": {
                "version": latest.version,
                "definition_format": latest.definition_format,
            },
            "automated_scan": {
                "overall_passed": report.overall_passed,
                "risk_score": report.risk_score,
                "no_secrets": report.no_secrets,
                "no_hardcoded_creds": report.no_hardcoded_creds,
                "valid_docker_syntax": report.valid_docker_syntax,
                "no_malicious_code": report.no_malicious_code,
                "recommendations": report.recommendations,
            },
            "saved_review_id": saved_review,
            "stack_definition_for_ai_review": latest.stack_definition,
            "ai_review_instructions": "The automated scan above covers pattern-based checks. As an AI reviewer, please additionally analyze: 1) Whether the service architecture makes sense and is secure, 2) If environment variables have sensible defaults, 3) If there are any data exfiltration risks, 4) If resource limits are appropriate, 5) If the network topology is secure (unnecessary exposed ports), 6) Any other security concerns that static analysis cannot catch.",
        });

        Ok(ToolContent::Text {
            text: serde_json::to_string(&result).unwrap(),
        })
    }

    fn schema(&self) -> Tool {
        Tool {
            name: "admin_validate_template_security".to_string(),
            description: "Run automated security validation on a template's stack definition. Checks for hardcoded secrets, credentials, Docker syntax issues, and malicious patterns (privileged containers, host mounts, crypto miners). Returns both the automated scan report and the raw stack_definition for AI to perform deeper semantic security analysis. Saves the security checklist to the review history.".to_string(),
            input_schema: json!({
                "type": "object",
                "properties": {
                    "template_id": {
                        "type": "string",
                        "description": "UUID of the template to security-scan"
                    },
                    "save_report": {
                        "type": "boolean",
                        "description": "Whether to save the scan result as a review record (default: true)"
                    }
                },
                "required": ["template_id"]
            }),
        }
    }
}
