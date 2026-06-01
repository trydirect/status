use actix_web::{dev::ServiceRequest, http::header::HeaderName};
use std::str::FromStr;

pub fn get_header<T>(req: &ServiceRequest, header_name: &'static str) -> Result<Option<T>, String>
where
    T: FromStr,
{
    let header_value = req.headers().get(HeaderName::from_static(header_name));

    if header_value.is_none() {
        return Ok(None);
    }

    header_value
        .unwrap()
        .to_str()
        .map_err(|_| format!("header {header_name} can't be converted to string"))?
        .parse::<T>()
        .map_err(|_| format!("header {header_name} has wrong type"))
        .map(|v| Some(v))
}
