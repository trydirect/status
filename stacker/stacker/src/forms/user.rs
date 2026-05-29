use crate::models::user::User as UserModel;
use serde_derive::{Deserialize, Serialize};
use serde_json::Value;
use serde_valid::Validate;

#[derive(Default, Debug, Clone, PartialEq, Serialize, Deserialize)]
#[serde(rename_all = "camelCase")]
pub struct UserForm {
    pub user: User,
}

//todo deref for UserForm. userForm.id, userForm.first_name

#[derive(Default, Debug, Clone, PartialEq, Serialize, Deserialize, Validate)]
#[serde(rename_all = "camelCase")]
pub struct User {
    #[serde(rename = "_id")]
    pub id: String,
    #[serde(rename = "first_name")]
    pub first_name: Option<String>,
    #[serde(rename = "last_name")]
    pub last_name: Option<String>,
    pub created: Option<String>,
    pub updated: Option<String>,
    pub email: String,
    #[serde(rename = "email_confirmed")]
    pub email_confirmed: bool,
    #[serde(default, alias = "mfaVerified", alias = "mfa_verified")]
    pub mfa_verified: Option<bool>,
    #[serde(default, alias = "twoFactorVerified", alias = "two_factor_verified")]
    pub two_factor_verified: Option<bool>,
    pub social: Option<bool>,
    pub website: Option<String>,
    pub currency: Value,
    pub phone: Option<String>,
    #[serde(rename = "password_change_required")]
    pub password_change_required: Value,
    pub photo: Option<String>,
    pub country: Option<String>,
    #[serde(rename = "billing_first_name")]
    pub billing_first_name: Value,
    #[serde(rename = "billing_last_name")]
    pub billing_last_name: Value,
    #[serde(rename = "billing_postcode")]
    pub billing_postcode: Option<String>,
    #[serde(rename = "billing_address_1")]
    pub billing_address_1: Option<String>,
    #[serde(rename = "billing_address_2")]
    pub billing_address_2: Option<String>,
    #[serde(rename = "billing_city")]
    pub billing_city: Option<String>,
    #[serde(rename = "billing_country_code")]
    pub billing_country_code: Option<String>,
    #[serde(rename = "billing_country_area")]
    pub billing_country_area: Option<String>,
    pub tokens: Option<Vec<Token>>,
    pub subscriptions: Option<Vec<Subscription>>,
    pub plan: Option<Plan>,
    #[serde(rename = "deployments_left")]
    pub deployments_left: Value,
    #[serde(rename = "suspension_hints")]
    pub suspension_hints: Option<SuspensionHints>,
    pub role: String,
}

#[derive(Default, Debug, Clone, PartialEq, Serialize, Deserialize)]
#[serde(rename_all = "camelCase")]
pub struct Token {
    pub provider: String,
    pub expired: bool,
}

#[derive(Default, Debug, Clone, PartialEq, Serialize, Deserialize)]
#[serde(rename_all = "camelCase")]
pub struct Subscription {
    #[serde(rename = "subscription_id")]
    pub subscription_id: i64,
    #[serde(rename = "user_id")]
    pub user_id: i64,
    #[serde(rename = "date_created")]
    pub date_created: Option<String>,
    #[serde(rename = "date_updated")]
    pub date_updated: Option<String>,
}

#[derive(Default, Debug, Clone, PartialEq, Serialize, Deserialize)]
#[serde(rename_all = "camelCase")]
pub struct Plan {
    #[serde(rename = "supported_stacks")]
    pub supported_stacks: SupportedStacks,
    #[serde(rename = "date_end")]
    pub date_end: Value,
    pub name: String,
    pub code: String,
    pub includes: Vec<Include>,
    pub team: String,
    #[serde(rename = "billing_email")]
    pub billing_email: String,
    #[serde(rename = "date_of_purchase")]
    pub date_of_purchase: String,
    pub currency: Option<String>,
    pub price: Option<String>,
    pub period: Option<String>,
    #[serde(rename = "date_start")]
    pub date_start: String,
    pub active: bool,
    #[serde(rename = "billing_id")]
    pub billing_id: Option<String>,
}

#[derive(Default, Debug, Clone, PartialEq, Serialize, Deserialize)]
#[serde(rename_all = "camelCase")]
pub struct SupportedStacks {
    pub monthly: Option<i64>,
    pub annually: Option<i64>,
}

#[derive(Default, Debug, Clone, PartialEq, Serialize, Deserialize)]
#[serde(rename_all = "camelCase")]
pub struct Include {
    pub name: String,
    pub code: String,
}

#[derive(Default, Debug, Clone, PartialEq, Serialize, Deserialize)]
#[serde(rename_all = "camelCase")]
pub struct SuspensionHints {
    pub days: i64,
    pub reason: String,
}

impl TryInto<UserModel> for UserForm {
    type Error = String;
    fn try_into(self) -> Result<UserModel, Self::Error> {
        Ok(UserModel {
            id: self.user.id,
            first_name: self.user.first_name.unwrap_or("Noname".to_string()),
            last_name: self.user.last_name.unwrap_or("Noname".to_string()),
            email: self.user.email,
            email_confirmed: self.user.email_confirmed,
            role: self.user.role,
            mfa_verified: self.user.mfa_verified.unwrap_or(false)
                || self.user.two_factor_verified.unwrap_or(false),
            access_token: None,
        })
    }
}
