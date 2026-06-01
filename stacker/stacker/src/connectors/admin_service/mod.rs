//! Admin Service connector module
//!
//! Provides helper utilities for authenticating internal admin services via JWT tokens.

pub mod jwt;

pub use jwt::{
    extract_bearer_token, parse_jwt_claims, user_from_jwt_claims, validate_jwt_expiration,
    JwtClaims,
};
