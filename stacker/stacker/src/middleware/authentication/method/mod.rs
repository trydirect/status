mod f_agent;
mod f_anonym;
mod f_cookie;
mod f_hmac;
mod f_jwt;
mod f_oauth;
mod f_query;

pub use f_agent::try_agent;
pub use f_anonym::anonym;
pub use f_cookie::try_cookie;
pub use f_hmac::try_hmac;
pub use f_jwt::try_jwt;
pub use f_oauth::{try_oauth, OAuthCache};
pub use f_query::try_query;
