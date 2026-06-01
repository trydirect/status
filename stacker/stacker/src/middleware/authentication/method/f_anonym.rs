use actix_web::dev::ServiceRequest;
use actix_web::HttpMessage;

#[tracing::instrument(name = "authenticate as anonym")]
pub fn anonym(req: &mut ServiceRequest) -> Result<bool, String> {
    let accesscontrol_vals = actix_casbin_auth::CasbinVals {
        subject: "anonym".to_string(),
        domain: None,
    };
    if req.extensions_mut().insert(accesscontrol_vals).is_some() {
        return Err("sth wrong with access control".to_string());
    }

    Ok(true)
}
