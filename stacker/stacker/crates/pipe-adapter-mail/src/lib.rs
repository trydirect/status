use async_native_tls::TlsConnector;
use async_std::net::TcpStream;
use async_trait::async_trait;
use futures_util::{AsyncRead, AsyncWrite, TryStreamExt};
use lettre::message::{header::ContentType, Mailbox, MultiPart, SinglePart};
use lettre::transport::smtp::authentication::Credentials;
use lettre::{AsyncSmtpTransport, AsyncTransport, Message, Tokio1Executor};
use mailparse::{addrparse_header, parse_mail, MailAddr, MailHeaderMap, ParsedMail};
use pipe_adapter_sdk::{
    builtin_registry, NormalizedMailAddress, NormalizedMailAttachment, NormalizedMailBody,
    NormalizedMailMessage, PipeAdapterCatalog, PipeAdapterDispatch, PipeAdapterError,
    PipeAdapterMetadata, PipeAdapterPayload, PipeAdapterReference, PipeSourceAdapter,
    PipeTargetAdapter,
};
use serde::Deserialize;
use serde_json::{json, Value};
use std::collections::HashSet;
use std::sync::{Arc, Mutex};

#[derive(Debug, Clone, PartialEq, Eq)]
pub struct SmtpDeliveryRequest {
    pub host: String,
    pub port: u16,
    pub username: Option<String>,
    pub password: Option<String>,
    pub from: String,
    pub to: Vec<String>,
    pub reply_to: Option<String>,
    pub subject: String,
    pub body_text: Option<String>,
    pub body_html: Option<String>,
    pub tls: bool,
}

#[derive(Debug, Clone, PartialEq, Eq)]
pub struct SmtpDeliveryReceipt {
    pub message_id: Option<String>,
    pub accepted_recipients: usize,
}

#[async_trait]
pub trait SmtpClient: Send + Sync + Clone + 'static {
    async fn send(
        &self,
        request: &SmtpDeliveryRequest,
    ) -> Result<SmtpDeliveryReceipt, PipeAdapterError>;
}

#[derive(Debug, Clone, PartialEq, Eq)]
pub struct MailSourceRequest {
    pub host: String,
    pub port: u16,
    pub username: String,
    pub password: Option<String>,
    pub tls: bool,
    pub mailbox: Option<String>,
}

#[async_trait]
pub trait MailSourceClient: Send + Sync + Clone + 'static {
    async fn poll_imap(
        &self,
        request: &MailSourceRequest,
    ) -> Result<Vec<NormalizedMailMessage>, PipeAdapterError>;

    async fn poll_pop3(
        &self,
        request: &MailSourceRequest,
    ) -> Result<Vec<NormalizedMailMessage>, PipeAdapterError>;
}

#[derive(Debug, Clone, Default)]
pub struct LiveMailSourceClient;

#[async_trait]
impl MailSourceClient for LiveMailSourceClient {
    async fn poll_imap(
        &self,
        request: &MailSourceRequest,
    ) -> Result<Vec<NormalizedMailMessage>, PipeAdapterError> {
        let stream = TcpStream::connect((request.host.as_str(), request.port))
            .await
            .map_err(|err| {
                PipeAdapterError::Message(format!(
                    "imap adapter failed to connect to {}:{}: {}",
                    request.host, request.port, err
                ))
            })?;
        if request.tls {
            let tls_stream = TlsConnector::new()
                .connect(&request.host, stream)
                .await
                .map_err(|err| {
                    PipeAdapterError::Message(format!(
                        "imap adapter failed to negotiate tls with {}:{}: {}",
                        request.host, request.port, err
                    ))
                })?;
            poll_imap_client(async_imap::Client::new(tls_stream), request).await
        } else {
            poll_imap_client(async_imap::Client::new(stream), request).await
        }
    }

    async fn poll_pop3(
        &self,
        request: &MailSourceRequest,
    ) -> Result<Vec<NormalizedMailMessage>, PipeAdapterError> {
        if request.tls {
            let tls = TlsConnector::new();
            let mut client =
                async_pop::connect((request.host.as_str(), request.port), &request.host, &tls)
                    .await
                    .map_err(|err| {
                        PipeAdapterError::Message(format!(
                            "pop3 adapter failed to connect to {}:{}: {}",
                            request.host, request.port, err
                        ))
                    })?;
            poll_pop3_client(&mut client, request).await
        } else {
            let mut client = async_pop::connect_plain((request.host.as_str(), request.port))
                .await
                .map_err(|err| {
                    PipeAdapterError::Message(format!(
                        "pop3 adapter failed to connect to {}:{}: {}",
                        request.host, request.port, err
                    ))
                })?;
            poll_pop3_client(&mut client, request).await
        }
    }
}

async fn poll_pop3_client<S>(
    client: &mut async_pop::Client<S>,
    request: &MailSourceRequest,
) -> Result<Vec<NormalizedMailMessage>, PipeAdapterError>
where
    S: AsyncRead + AsyncWrite + Unpin + Send,
{
    let password = request.password.as_deref().ok_or_else(|| {
        PipeAdapterError::Message(
            "pop3 adapter requires a password in the adapter configuration".to_string(),
        )
    })?;

    client
        .login(request.username.as_str(), password)
        .await
        .map_err(|err| {
            PipeAdapterError::Message(format!(
                "pop3 adapter login failed for '{}' on {}:{}: {}",
                request.username, request.host, request.port, err
            ))
        })?;

    let entries = client.uidl(None).await.map_err(|err| {
        PipeAdapterError::Message(format!(
            "pop3 adapter failed to list mailbox on {}:{}: {}",
            request.host, request.port, err
        ))
    })?;

    let items = match entries {
        async_pop::response::uidl::UidlResponse::Multiple(entries) => {
            let mut items = Vec::new();
            for entry in entries.items() {
                let index = entry.index().to_string().parse::<usize>().map_err(|err| {
                    PipeAdapterError::Message(format!(
                        "pop3 adapter returned invalid message index '{}': {}",
                        entry.index(),
                        err
                    ))
                })?;
                items.push((index, entry.id().to_string()));
            }
            items
        }
        async_pop::response::uidl::UidlResponse::Single(entry) => {
            let index = entry.index().to_string().parse::<usize>().map_err(|err| {
                PipeAdapterError::Message(format!(
                    "pop3 adapter returned invalid message index '{}': {}",
                    entry.index(),
                    err
                ))
            })?;
            vec![(index, entry.id().to_string())]
        }
    };

    let mut messages = Vec::new();
    for (index, uid) in items {
        let raw = client.retr(index).await.map_err(|err| {
            PipeAdapterError::Message(format!(
                "pop3 adapter failed to retrieve message {} from {}:{}: {}",
                index, request.host, request.port, err
            ))
        })?;
        messages.push(parse_normalized_mail_message(
            raw.as_ref(),
            None,
            Some(uid),
        )?);
    }

    let _ = client.quit().await;
    Ok(messages)
}

#[derive(Debug, Clone, Default)]
pub struct LettreSmtpClient;

#[async_trait]
impl SmtpClient for LettreSmtpClient {
    async fn send(
        &self,
        request: &SmtpDeliveryRequest,
    ) -> Result<SmtpDeliveryReceipt, PipeAdapterError> {
        let email = build_smtp_message(request)?;
        let mut builder = if request.tls {
            AsyncSmtpTransport::<Tokio1Executor>::relay(&request.host)
                .map_err(|err| {
                    PipeAdapterError::Message(format!(
                        "invalid smtp host '{}': {}",
                        request.host, err
                    ))
                })?
                .port(request.port)
        } else {
            AsyncSmtpTransport::<Tokio1Executor>::builder_dangerous(&request.host)
                .port(request.port)
        };

        match (&request.username, &request.password) {
            (Some(username), Some(password)) => {
                builder = builder.credentials(Credentials::new(username.clone(), password.clone()));
            }
            (None, None) => {}
            _ => {
                return Err(PipeAdapterError::Message(
                    "smtp adapter requires both username and password when credentials are configured".to_string(),
                ));
            }
        }

        let response =
            builder.build().send(email).await.map_err(|err| {
                PipeAdapterError::Message(format!("smtp delivery failed: {}", err))
            })?;

        let mut messages = response.message();
        Ok(SmtpDeliveryReceipt {
            message_id: messages.next().map(str::to_owned),
            accepted_recipients: request.to.len(),
        })
    }
}

#[derive(Debug, Clone)]
pub struct SmtpTargetAdapter<T = LettreSmtpClient> {
    metadata: PipeAdapterMetadata,
    reference: PipeAdapterReference,
    config: SmtpTargetConfig,
    client: T,
}

#[derive(Debug, Clone)]
pub struct ImapSourceAdapter<T = LiveMailSourceClient> {
    metadata: PipeAdapterMetadata,
    reference: PipeAdapterReference,
    config: ImapSourceConfig,
    client: T,
    seen_ids: Arc<Mutex<HashSet<String>>>,
}

#[derive(Debug, Clone)]
pub struct Pop3SourceAdapter<T = LiveMailSourceClient> {
    metadata: PipeAdapterMetadata,
    reference: PipeAdapterReference,
    config: Pop3SourceConfig,
    client: T,
    seen_ids: Arc<Mutex<HashSet<String>>>,
}

impl SmtpTargetAdapter<LettreSmtpClient> {
    pub fn from_reference(reference: PipeAdapterReference) -> Result<Self, PipeAdapterError> {
        Self::with_client(reference, LettreSmtpClient)
    }
}

impl ImapSourceAdapter<LiveMailSourceClient> {
    pub fn from_reference(reference: PipeAdapterReference) -> Result<Self, PipeAdapterError> {
        Self::with_client(reference, LiveMailSourceClient)
    }
}

impl Pop3SourceAdapter<LiveMailSourceClient> {
    pub fn from_reference(reference: PipeAdapterReference) -> Result<Self, PipeAdapterError> {
        Self::with_client(reference, LiveMailSourceClient)
    }
}

impl<T: SmtpClient> SmtpTargetAdapter<T> {
    pub fn with_client(
        reference: PipeAdapterReference,
        client: T,
    ) -> Result<Self, PipeAdapterError> {
        let metadata = builtin_registry().find(&reference.code).ok_or_else(|| {
            PipeAdapterError::Message(format!("unknown smtp adapter '{}'", reference.code))
        })?;
        let config_value = reference.config.clone().ok_or_else(|| {
            PipeAdapterError::Message(format!("adapter '{}' requires config", reference.code))
        })?;
        let config: SmtpTargetConfig = serde_json::from_value(config_value).map_err(|err| {
            PipeAdapterError::Message(format!(
                "invalid smtp adapter config for '{}': {}",
                reference.code, err
            ))
        })?;

        Ok(Self {
            metadata,
            reference,
            config,
            client,
        })
    }

    fn build_request(
        &self,
        payload: PipeAdapterPayload,
    ) -> Result<SmtpDeliveryRequest, PipeAdapterError> {
        let envelope = match payload {
            PipeAdapterPayload::Json(value) => SmtpEnvelope::from_json(value, &self.config)?,
            PipeAdapterPayload::MailMessage(message) => {
                SmtpEnvelope::from_message(*message, &self.config)?
            }
        };

        Ok(SmtpDeliveryRequest {
            host: self.config.host.clone(),
            port: self.config.port,
            username: self.config.username.clone(),
            password: self.config.password.clone(),
            from: envelope.from,
            to: envelope.to,
            reply_to: envelope.reply_to,
            subject: envelope.subject,
            body_text: envelope.body_text,
            body_html: envelope.body_html,
            tls: self.config.tls,
        })
    }
}

impl<T: MailSourceClient> ImapSourceAdapter<T> {
    pub fn with_client(
        reference: PipeAdapterReference,
        client: T,
    ) -> Result<Self, PipeAdapterError> {
        let metadata = builtin_registry().find(&reference.code).ok_or_else(|| {
            PipeAdapterError::Message(format!("unknown imap adapter '{}'", reference.code))
        })?;
        let config_value = reference.config.clone().ok_or_else(|| {
            PipeAdapterError::Message(format!("adapter '{}' requires config", reference.code))
        })?;
        let config: ImapSourceConfig = serde_json::from_value(config_value).map_err(|err| {
            PipeAdapterError::Message(format!(
                "invalid imap adapter config for '{}': {}",
                reference.code, err
            ))
        })?;

        Ok(Self {
            metadata,
            reference,
            config,
            client,
            seen_ids: Arc::new(Mutex::new(HashSet::new())),
        })
    }

    fn build_request(&self) -> MailSourceRequest {
        MailSourceRequest {
            host: self.config.host.clone(),
            port: self.config.port,
            username: self.config.username.clone(),
            password: self.config.password.clone(),
            tls: self.config.tls,
            mailbox: Some(self.config.mailbox.clone()),
        }
    }
}

impl<T: MailSourceClient> Pop3SourceAdapter<T> {
    pub fn with_client(
        reference: PipeAdapterReference,
        client: T,
    ) -> Result<Self, PipeAdapterError> {
        let metadata = builtin_registry().find(&reference.code).ok_or_else(|| {
            PipeAdapterError::Message(format!("unknown pop3 adapter '{}'", reference.code))
        })?;
        let config_value = reference.config.clone().ok_or_else(|| {
            PipeAdapterError::Message(format!("adapter '{}' requires config", reference.code))
        })?;
        let config: Pop3SourceConfig = serde_json::from_value(config_value).map_err(|err| {
            PipeAdapterError::Message(format!(
                "invalid pop3 adapter config for '{}': {}",
                reference.code, err
            ))
        })?;

        Ok(Self {
            metadata,
            reference,
            config,
            client,
            seen_ids: Arc::new(Mutex::new(HashSet::new())),
        })
    }

    fn build_request(&self) -> MailSourceRequest {
        MailSourceRequest {
            host: self.config.host.clone(),
            port: self.config.port,
            username: self.config.username.clone(),
            password: self.config.password.clone(),
            tls: self.config.tls,
            mailbox: None,
        }
    }
}

#[async_trait]
impl<T: SmtpClient> PipeTargetAdapter for SmtpTargetAdapter<T> {
    fn metadata(&self) -> &PipeAdapterMetadata {
        &self.metadata
    }

    async fn deliver(&self, payload: PipeAdapterPayload) -> Result<Value, PipeAdapterError> {
        let request = self.build_request(payload)?;
        let receipt = self.client.send(&request).await?;
        Ok(json!({
            "transport": "smtp",
            "adapter": self.reference.code,
            "status": Value::Null,
            "delivered": true,
            "body": {
                "host": request.host,
                "port": request.port,
                "tls": request.tls,
                "subject": request.subject,
                "to": request.to,
                "from": request.from,
                "message_id": receipt.message_id,
                "accepted_recipients": receipt.accepted_recipients,
            }
        }))
    }
}

#[async_trait]
impl<T: MailSourceClient> PipeSourceAdapter for ImapSourceAdapter<T> {
    fn metadata(&self) -> &PipeAdapterMetadata {
        &self.metadata
    }

    async fn poll(&self) -> Result<Vec<PipeAdapterDispatch>, PipeAdapterError> {
        let messages = filter_new_messages(
            &self.seen_ids,
            self.client.poll_imap(&self.build_request()).await?,
        )?;
        Ok(messages
            .into_iter()
            .map(|message| PipeAdapterDispatch {
                adapter: self.reference.clone(),
                payload: PipeAdapterPayload::MailMessage(Box::new(message)),
            })
            .collect())
    }
}

#[async_trait]
impl<T: MailSourceClient> PipeSourceAdapter for Pop3SourceAdapter<T> {
    fn metadata(&self) -> &PipeAdapterMetadata {
        &self.metadata
    }

    async fn poll(&self) -> Result<Vec<PipeAdapterDispatch>, PipeAdapterError> {
        let messages = filter_new_messages(
            &self.seen_ids,
            self.client.poll_pop3(&self.build_request()).await?,
        )?;
        Ok(messages
            .into_iter()
            .map(|message| PipeAdapterDispatch {
                adapter: self.reference.clone(),
                payload: PipeAdapterPayload::MailMessage(Box::new(message)),
            })
            .collect())
    }
}

#[derive(Debug, Clone, Deserialize)]
struct SmtpTargetConfig {
    host: String,
    #[serde(default = "default_smtp_port")]
    port: u16,
    #[serde(default)]
    username: Option<String>,
    #[serde(default)]
    password: Option<String>,
    #[serde(default)]
    from: Option<String>,
    #[serde(default, deserialize_with = "deserialize_string_or_vec")]
    to: Vec<String>,
    #[serde(default = "default_true")]
    tls: bool,
}

#[derive(Debug, Clone, Deserialize)]
struct ImapSourceConfig {
    host: String,
    #[serde(default = "default_imap_port")]
    port: u16,
    username: String,
    #[serde(default)]
    password: Option<String>,
    #[serde(default = "default_imap_mailbox")]
    mailbox: String,
    #[serde(default = "default_true")]
    tls: bool,
}

#[derive(Debug, Clone, Deserialize)]
struct Pop3SourceConfig {
    host: String,
    #[serde(default = "default_pop3_port")]
    port: u16,
    username: String,
    #[serde(default)]
    password: Option<String>,
    #[serde(default = "default_true")]
    tls: bool,
}

#[derive(Debug, Clone)]
struct SmtpEnvelope {
    from: String,
    to: Vec<String>,
    reply_to: Option<String>,
    subject: String,
    body_text: Option<String>,
    body_html: Option<String>,
}

impl SmtpEnvelope {
    fn from_json(value: Value, config: &SmtpTargetConfig) -> Result<Self, PipeAdapterError> {
        let from = json_string_field(&value, "from_email")
            .or_else(|| config.from.clone())
            .ok_or_else(|| {
                PipeAdapterError::Message("smtp adapter requires a from address".to_string())
            })?;
        let to = json_string_list_field(&value, "to_email");
        let to = if to.is_empty() { config.to.clone() } else { to };
        if to.is_empty() {
            return Err(PipeAdapterError::Message(
                "smtp adapter requires at least one recipient address".to_string(),
            ));
        }

        let subject = json_string_field(&value, "subject")
            .unwrap_or_else(|| "Stacker pipe message".to_string());
        let body_text = json_string_field(&value, "body_text").or_else(|| match &value {
            Value::String(text) => Some(text.clone()),
            other => serde_json::to_string_pretty(other).ok(),
        });
        let body_html = json_string_field(&value, "body_html");
        if body_text.is_none() && body_html.is_none() {
            return Err(PipeAdapterError::Message(
                "smtp adapter requires body_text or body_html content".to_string(),
            ));
        }

        Ok(Self {
            from,
            to,
            reply_to: json_string_field(&value, "reply_to_email"),
            subject,
            body_text,
            body_html,
        })
    }

    fn from_message(
        message: pipe_adapter_sdk::NormalizedMailMessage,
        config: &SmtpTargetConfig,
    ) -> Result<Self, PipeAdapterError> {
        let from = message
            .from
            .first()
            .map(|address| address.email.clone())
            .or_else(|| config.from.clone())
            .ok_or_else(|| {
                PipeAdapterError::Message("smtp adapter requires a from address".to_string())
            })?;
        let to = if message.to.is_empty() {
            config.to.clone()
        } else {
            message
                .to
                .into_iter()
                .map(|address| address.email)
                .collect()
        };
        if to.is_empty() {
            return Err(PipeAdapterError::Message(
                "smtp adapter requires at least one recipient address".to_string(),
            ));
        }

        let subject = message
            .subject
            .unwrap_or_else(|| "Stacker pipe message".to_string());
        let body_text = message.body.text;
        let body_html = message.body.html;
        if body_text.is_none() && body_html.is_none() {
            return Err(PipeAdapterError::Message(
                "smtp adapter requires body_text or body_html content".to_string(),
            ));
        }

        Ok(Self {
            from,
            to,
            reply_to: None,
            subject,
            body_text,
            body_html,
        })
    }
}

fn default_smtp_port() -> u16 {
    587
}

fn default_imap_port() -> u16 {
    993
}

fn default_pop3_port() -> u16 {
    995
}

fn default_imap_mailbox() -> String {
    "INBOX".to_string()
}

fn default_true() -> bool {
    true
}

fn deserialize_string_or_vec<'de, D>(deserializer: D) -> Result<Vec<String>, D::Error>
where
    D: serde::Deserializer<'de>,
{
    let value = Option::<Value>::deserialize(deserializer)?;
    Ok(match value {
        Some(Value::String(item)) => vec![item],
        Some(Value::Array(items)) => items
            .into_iter()
            .filter_map(|item| item.as_str().map(str::to_string))
            .collect(),
        _ => Vec::new(),
    })
}

fn json_string_field(value: &Value, key: &str) -> Option<String> {
    value
        .get(key)
        .and_then(Value::as_str)
        .map(str::trim)
        .filter(|value| !value.is_empty())
        .map(str::to_string)
}

fn json_string_list_field(value: &Value, key: &str) -> Vec<String> {
    match value.get(key) {
        Some(Value::String(item)) if !item.trim().is_empty() => vec![item.trim().to_string()],
        Some(Value::Array(items)) => items
            .iter()
            .filter_map(Value::as_str)
            .map(str::trim)
            .filter(|item| !item.is_empty())
            .map(str::to_string)
            .collect(),
        _ => Vec::new(),
    }
}

async fn poll_imap_client<S>(
    mut client: async_imap::Client<S>,
    request: &MailSourceRequest,
) -> Result<Vec<NormalizedMailMessage>, PipeAdapterError>
where
    S: AsyncRead + AsyncWrite + Unpin + Send + std::fmt::Debug,
{
    let password = request.password.as_deref().ok_or_else(|| {
        PipeAdapterError::Message(
            "imap adapter requires a password in the adapter configuration".to_string(),
        )
    })?;
    client.read_response().await.map_err(|err| {
        PipeAdapterError::Message(format!(
            "imap adapter failed to read greeting from {}:{}: {}",
            request.host, request.port, err
        ))
    })?;
    let mut session = client
        .login(request.username.as_str(), password)
        .await
        .map_err(|(err, _)| {
            PipeAdapterError::Message(format!(
                "imap adapter login failed for '{}' on {}:{}: {}",
                request.username, request.host, request.port, err
            ))
        })?;

    let mailbox = request.mailbox.as_deref().unwrap_or("INBOX");
    session.select(mailbox).await.map_err(|err| {
        PipeAdapterError::Message(format!(
            "imap adapter failed to select mailbox '{}': {}",
            mailbox, err
        ))
    })?;

    let mut uids: Vec<_> = session
        .uid_search("UNSEEN")
        .await
        .map_err(|err| {
            PipeAdapterError::Message(format!(
                "imap adapter failed to search mailbox '{}': {}",
                mailbox, err
            ))
        })?
        .into_iter()
        .collect();
    uids.sort_unstable();

    let mut messages = Vec::new();
    for uid in uids {
        let fetches: Vec<_> = session
            .uid_fetch(uid.to_string(), "RFC822")
            .await
            .map_err(|err| {
                PipeAdapterError::Message(format!(
                    "imap adapter failed to fetch uid {} from '{}': {}",
                    uid, mailbox, err
                ))
            })?
            .try_collect()
            .await
            .map_err(|err| {
                PipeAdapterError::Message(format!(
                    "imap adapter failed to decode uid {} from '{}': {}",
                    uid, mailbox, err
                ))
            })?;

        for fetch in fetches {
            if let Some(body) = fetch.body() {
                messages.push(parse_normalized_mail_message(
                    body,
                    Some(mailbox),
                    Some(uid.to_string()),
                )?);
            }
        }

        let _: Vec<_> = session
            .uid_store(uid.to_string(), "+FLAGS (\\Seen)")
            .await
            .map_err(|err| {
                PipeAdapterError::Message(format!(
                    "imap adapter failed to mark uid {} seen in '{}': {}",
                    uid, mailbox, err
                ))
            })?
            .try_collect()
            .await
            .map_err(|err| {
                PipeAdapterError::Message(format!(
                    "imap adapter failed to confirm seen flag for uid {} in '{}': {}",
                    uid, mailbox, err
                ))
            })?;
    }

    let _ = session.logout().await;
    Ok(messages)
}

fn filter_new_messages(
    seen_ids: &Arc<Mutex<HashSet<String>>>,
    messages: Vec<NormalizedMailMessage>,
) -> Result<Vec<NormalizedMailMessage>, PipeAdapterError> {
    let mut seen_ids = seen_ids
        .lock()
        .map_err(|_| PipeAdapterError::Message("mail adapter state lock poisoned".to_string()))?;
    let mut fresh = Vec::new();

    for message in messages {
        let dedupe_key = message
            .cursor
            .clone()
            .or_else(|| message.message_id.clone())
            .or_else(|| message.subject.clone())
            .ok_or_else(|| {
                PipeAdapterError::Message(
                    "mail adapter could not derive a stable cursor or message id".to_string(),
                )
            })?;
        if seen_ids.insert(dedupe_key) {
            fresh.push(message);
        }
    }

    Ok(fresh)
}

fn parse_normalized_mail_message(
    raw: &[u8],
    mailbox: Option<&str>,
    cursor: Option<String>,
) -> Result<NormalizedMailMessage, PipeAdapterError> {
    let parsed = parse_mail(raw).map_err(|err| {
        PipeAdapterError::Message(format!("mail adapter failed to parse raw message: {}", err))
    })?;
    let body = extract_mail_body(&parsed);

    Ok(NormalizedMailMessage {
        cursor,
        mailbox: mailbox.map(str::to_string),
        message_id: parsed.headers.get_first_value("Message-ID"),
        subject: parsed.headers.get_first_value("Subject"),
        sent_at: parsed.headers.get_first_value("Date"),
        received_at: None,
        from: parse_mail_addresses(&parsed, "From")?,
        to: parse_mail_addresses(&parsed, "To")?,
        cc: parse_mail_addresses(&parsed, "Cc")?,
        bcc: parse_mail_addresses(&parsed, "Bcc")?,
        headers: parsed
            .headers
            .iter()
            .map(|header| (header.get_key().to_string(), header.get_value()))
            .collect(),
        body,
        attachments: extract_attachments(&parsed)?,
    })
}

fn extract_mail_body(parsed: &ParsedMail<'_>) -> NormalizedMailBody {
    let mut body = NormalizedMailBody {
        text: None,
        html: None,
    };

    for part in parsed.parts() {
        if part.ctype.mimetype.eq_ignore_ascii_case("text/plain") && body.text.is_none() {
            if let Ok(text) = part.get_body() {
                let text = text.trim().to_string();
                if !text.is_empty() {
                    body.text = Some(text);
                }
            }
        }
        if part.ctype.mimetype.eq_ignore_ascii_case("text/html") && body.html.is_none() {
            if let Ok(html) = part.get_body() {
                let html = html.trim().to_string();
                if !html.is_empty() {
                    body.html = Some(html);
                }
            }
        }
    }

    if body.text.is_none() && body.html.is_none() && parsed.subparts.is_empty() {
        if let Ok(text) = parsed.get_body() {
            let text = text.trim().to_string();
            if !text.is_empty() {
                body.text = Some(text);
            }
        }
    }

    body
}

fn extract_attachments(
    parsed: &ParsedMail<'_>,
) -> Result<Vec<NormalizedMailAttachment>, PipeAdapterError> {
    let mut attachments = Vec::new();

    for part in parsed.parts() {
        if part.ctype.mimetype.starts_with("multipart/") {
            continue;
        }
        let disposition = part.get_content_disposition();
        let filename = disposition
            .params
            .get("filename")
            .cloned()
            .or_else(|| part.ctype.params.get("name").cloned());
        if let Some(filename) = filename {
            let raw = part.get_body_raw().map_err(|err| {
                PipeAdapterError::Message(format!(
                    "mail adapter failed to decode attachment '{}': {}",
                    filename, err
                ))
            })?;
            attachments.push(NormalizedMailAttachment {
                file_name: Some(filename),
                content_type: Some(part.ctype.mimetype.clone()),
                size_bytes: Some(raw.len() as u64),
            });
        }
    }

    Ok(attachments)
}

fn parse_mail_addresses(
    parsed: &ParsedMail<'_>,
    header_name: &str,
) -> Result<Vec<NormalizedMailAddress>, PipeAdapterError> {
    let Some(header) = parsed
        .headers
        .iter()
        .find(|header| header.get_key_ref().eq_ignore_ascii_case(header_name))
    else {
        return Ok(Vec::new());
    };

    let addresses = addrparse_header(header).map_err(|err| {
        PipeAdapterError::Message(format!(
            "mail adapter failed to parse '{}' header: {}",
            header_name, err
        ))
    })?;

    Ok(addresses.iter().flat_map(flatten_mail_addr).collect())
}

fn flatten_mail_addr(address: &MailAddr) -> Vec<NormalizedMailAddress> {
    match address {
        MailAddr::Single(info) => vec![NormalizedMailAddress {
            name: info
                .display_name
                .clone()
                .filter(|name| !name.trim().is_empty()),
            email: info.addr.clone(),
        }],
        MailAddr::Group(group) => group
            .addrs
            .iter()
            .map(|info| NormalizedMailAddress {
                name: info
                    .display_name
                    .clone()
                    .filter(|name| !name.trim().is_empty()),
                email: info.addr.clone(),
            })
            .collect(),
    }
}

fn build_smtp_message(request: &SmtpDeliveryRequest) -> Result<Message, PipeAdapterError> {
    let mut builder = Message::builder()
        .from(parse_mailbox(&request.from)?)
        .subject(request.subject.clone());

    for recipient in &request.to {
        builder = builder.to(parse_mailbox(recipient)?);
    }
    if let Some(reply_to) = &request.reply_to {
        builder = builder.reply_to(parse_mailbox(reply_to)?);
    }

    match (&request.body_text, &request.body_html) {
        (Some(text), Some(html)) => builder
            .multipart(
                MultiPart::alternative()
                    .singlepart(
                        SinglePart::builder()
                            .header(ContentType::TEXT_PLAIN)
                            .body(text.clone()),
                    )
                    .singlepart(
                        SinglePart::builder()
                            .header(ContentType::TEXT_HTML)
                            .body(html.clone()),
                    ),
            )
            .map_err(|err| {
                PipeAdapterError::Message(format!("failed to build smtp message: {}", err))
            }),
        (Some(text), None) => builder
            .singlepart(
                SinglePart::builder()
                    .header(ContentType::TEXT_PLAIN)
                    .body(text.clone()),
            )
            .map_err(|err| {
                PipeAdapterError::Message(format!("failed to build smtp message: {}", err))
            }),
        (None, Some(html)) => builder
            .singlepart(
                SinglePart::builder()
                    .header(ContentType::TEXT_HTML)
                    .body(html.clone()),
            )
            .map_err(|err| {
                PipeAdapterError::Message(format!("failed to build smtp message: {}", err))
            }),
        (None, None) => Err(PipeAdapterError::Message(
            "smtp adapter requires body_text or body_html content".to_string(),
        )),
    }
}

fn parse_mailbox(raw: &str) -> Result<Mailbox, PipeAdapterError> {
    raw.parse().map_err(|err| {
        PipeAdapterError::Message(format!("invalid email address '{}': {}", raw, err))
    })
}

#[cfg(test)]
mod tests {
    use super::*;
    use std::sync::{Arc, Mutex};

    #[derive(Clone, Default)]
    struct FakeSmtpClient {
        requests: Arc<Mutex<Vec<SmtpDeliveryRequest>>>,
    }

    #[derive(Clone, Default)]
    struct FakeMailSourceClient {
        imap_messages: Arc<Mutex<Vec<NormalizedMailMessage>>>,
        pop3_messages: Arc<Mutex<Vec<NormalizedMailMessage>>>,
    }

    #[async_trait]
    impl SmtpClient for FakeSmtpClient {
        async fn send(
            &self,
            request: &SmtpDeliveryRequest,
        ) -> Result<SmtpDeliveryReceipt, PipeAdapterError> {
            self.requests.lock().unwrap().push(request.clone());
            Ok(SmtpDeliveryReceipt {
                message_id: Some("msg-123".to_string()),
                accepted_recipients: request.to.len(),
            })
        }
    }

    #[async_trait]
    impl MailSourceClient for FakeMailSourceClient {
        async fn poll_imap(
            &self,
            _request: &MailSourceRequest,
        ) -> Result<Vec<NormalizedMailMessage>, PipeAdapterError> {
            Ok(self
                .imap_messages
                .lock()
                .expect("imap messages lock")
                .clone())
        }

        async fn poll_pop3(
            &self,
            _request: &MailSourceRequest,
        ) -> Result<Vec<NormalizedMailMessage>, PipeAdapterError> {
            Ok(self
                .pop3_messages
                .lock()
                .expect("pop3 messages lock")
                .clone())
        }
    }

    #[tokio::test]
    async fn smtp_target_adapter_delivers_json_payload_with_fake_client() {
        let client = FakeSmtpClient::default();
        let adapter = SmtpTargetAdapter::with_client(
            PipeAdapterReference::new("smtp").with_config(json!({
                "host": "smtp.example.com",
                "port": 2525,
                "from": "noreply@example.com",
                "to": ["alerts@example.com"],
                "tls": false
            })),
            client.clone(),
        )
        .expect("adapter config should parse");

        let response = adapter
            .deliver(PipeAdapterPayload::Json(json!({
                "subject": "Deployment ready",
                "body_text": "The deployment completed successfully"
            })))
            .await
            .expect("smtp delivery should succeed");

        let requests = client.requests.lock().unwrap();
        assert_eq!(requests.len(), 1);
        assert_eq!(requests[0].host, "smtp.example.com");
        assert_eq!(requests[0].port, 2525);
        assert_eq!(requests[0].to, vec!["alerts@example.com".to_string()]);
        assert_eq!(requests[0].from, "noreply@example.com");
        assert_eq!(response["transport"], "smtp");
        assert_eq!(response["adapter"], "smtp");
        assert_eq!(response["delivered"], true);
        assert_eq!(response["body"]["accepted_recipients"], 1);
    }

    #[tokio::test]
    async fn smtp_target_adapter_requires_recipient_before_delivery() {
        let adapter = SmtpTargetAdapter::with_client(
            PipeAdapterReference::new("smtp").with_config(json!({
                "host": "smtp.example.com",
                "from": "noreply@example.com"
            })),
            FakeSmtpClient::default(),
        )
        .expect("adapter config should parse");

        let error = adapter
            .deliver(PipeAdapterPayload::Json(json!({
                "subject": "Deployment ready",
                "body_text": "The deployment completed successfully"
            })))
            .await
            .expect_err("delivery should fail without recipients");

        assert!(error
            .to_string()
            .contains("smtp adapter requires at least one recipient address"));
    }

    #[tokio::test]
    async fn imap_source_adapter_polls_normalized_mail_dispatches() {
        let client = FakeMailSourceClient {
            imap_messages: Arc::new(Mutex::new(vec![NormalizedMailMessage {
                subject: Some("Incident opened".to_string()),
                mailbox: Some("INBOX".to_string()),
                body: pipe_adapter_sdk::NormalizedMailBody {
                    text: Some("CPU usage exceeded threshold".to_string()),
                    html: None,
                },
                ..Default::default()
            }])),
            pop3_messages: Arc::new(Mutex::new(Vec::new())),
        };
        let adapter = ImapSourceAdapter::with_client(
            PipeAdapterReference::new("imap").with_config(json!({
                "host": "imap.example.com",
                "username": "alerts@example.com",
                "password": "secret",
                "mailbox": "INBOX"
            })),
            client,
        )
        .expect("imap adapter config should parse");

        let dispatches = adapter.poll().await.expect("imap poll should succeed");

        assert_eq!(dispatches.len(), 1);
        assert_eq!(dispatches[0].adapter.code, "imap");
        assert_eq!(
            dispatches[0].payload,
            PipeAdapterPayload::MailMessage(Box::new(NormalizedMailMessage {
                subject: Some("Incident opened".to_string()),
                mailbox: Some("INBOX".to_string()),
                body: pipe_adapter_sdk::NormalizedMailBody {
                    text: Some("CPU usage exceeded threshold".to_string()),
                    html: None,
                },
                ..Default::default()
            }))
        );
    }

    #[tokio::test]
    async fn pop3_source_adapter_polls_normalized_mail_dispatches() {
        let client = FakeMailSourceClient {
            imap_messages: Arc::new(Mutex::new(Vec::new())),
            pop3_messages: Arc::new(Mutex::new(vec![NormalizedMailMessage {
                subject: Some("Welcome".to_string()),
                body: pipe_adapter_sdk::NormalizedMailBody {
                    text: Some("hello".to_string()),
                    html: None,
                },
                ..Default::default()
            }])),
        };
        let adapter = Pop3SourceAdapter::with_client(
            PipeAdapterReference::new("pop3").with_config(json!({
                "host": "pop3.example.com",
                "username": "alerts@example.com",
                "password": "secret"
            })),
            client,
        )
        .expect("pop3 adapter config should parse");

        let dispatches = adapter.poll().await.expect("pop3 poll should succeed");

        assert_eq!(dispatches.len(), 1);
        assert_eq!(dispatches[0].adapter.code, "pop3");
        assert_eq!(
            dispatches[0].payload,
            PipeAdapterPayload::MailMessage(Box::new(NormalizedMailMessage {
                subject: Some("Welcome".to_string()),
                body: pipe_adapter_sdk::NormalizedMailBody {
                    text: Some("hello".to_string()),
                    html: None,
                },
                ..Default::default()
            }))
        );
    }
}
