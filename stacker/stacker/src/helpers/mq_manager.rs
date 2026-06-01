use deadpool_lapin::{Config, CreatePoolError, Object, Pool, Runtime};
use lapin::types::{AMQPValue, FieldTable};
use lapin::{
    options::*,
    publisher_confirm::{Confirmation, PublisherConfirm},
    BasicProperties, Channel, ExchangeKind,
};
use serde::ser::Serialize;

#[derive(Debug)]
pub struct MqManager {
    pool: Pool,
}

impl MqManager {
    pub fn try_new(url: String) -> Result<Self, std::io::Error> {
        let mut cfg = Config::default();
        cfg.url = Some(url);
        let pool = cfg.create_pool(Some(Runtime::Tokio1)).map_err(|err| {
            tracing::error!("{:?}", err);

            match err {
                CreatePoolError::Config(_) => {
                    std::io::Error::new(std::io::ErrorKind::Other, "config error")
                }
                CreatePoolError::Build(_) => {
                    std::io::Error::new(std::io::ErrorKind::Other, "build error")
                }
            }
        })?;

        Ok(Self { pool })
    }

    async fn get_connection(&self) -> Result<Object, String> {
        self.pool.get().await.map_err(|err| {
            let msg = format!("getting connection from pool {:?}", err);
            tracing::error!(msg);
            msg
        })
    }

    async fn create_channel(&self) -> Result<Channel, String> {
        self.get_connection()
            .await?
            .create_channel()
            .await
            .map_err(|err| {
                let msg = format!("creating RabbitMQ channel {:?}", err);
                tracing::error!(msg);
                msg
            })
    }

    async fn declare_exchange(channel: &Channel, exchange: &str) -> Result<(), String> {
        channel
            .exchange_declare(
                exchange,
                ExchangeKind::Topic,
                ExchangeDeclareOptions {
                    passive: false,
                    durable: true,
                    auto_delete: false,
                    internal: false,
                    nowait: false,
                },
                FieldTable::default(),
            )
            .await
            .map_err(|err| {
                let msg = format!("declaring exchange '{}': {:?}", exchange, err);
                tracing::error!(msg);
                msg
            })
    }

    pub async fn publish<T: ?Sized + Serialize>(
        &self,
        exchange: String,
        routing_key: String,
        msg: &T,
    ) -> Result<PublisherConfirm, String> {
        let payload = serde_json::to_string::<T>(msg).map_err(|err| format!("{:?}", err))?;

        let channel = self.create_channel().await?;
        Self::declare_exchange(&channel, &exchange).await?;
        channel
            .basic_publish(
                exchange.as_str(),
                routing_key.as_str(),
                BasicPublishOptions::default(),
                payload.as_bytes(),
                BasicProperties::default(),
            )
            .await
            .map_err(|err| {
                tracing::error!("publishing message {:?}", err);
                format!("publishing message {:?}", err)
            })
    }

    pub async fn publish_and_confirm<T: ?Sized + Serialize>(
        &self,
        exchange: String,
        routing_key: String,
        msg: &T,
    ) -> Result<(), String> {
        self.publish(exchange, routing_key, msg)
            .await?
            .await
            .map_err(|err| {
                let msg = format!("confirming the publication {:?}", err);
                tracing::error!(msg);
                msg
            })
            .and_then(|confirm| match confirm {
                Confirmation::NotRequested => {
                    let msg = format!("confirmation is NotRequested");
                    tracing::error!(msg);
                    Err(msg)
                }
                _ => Ok(()),
            })
    }

    pub async fn consume(
        &self,
        exchange_name: &str,
        queue_name: &str,
        routing_key: &str,
    ) -> Result<Channel, String> {
        let channel = self.create_channel().await?;

        Self::declare_exchange(&channel, exchange_name)
            .await
            .map_err(|e| {
                tracing::error!("Exchange declare failed: {}", e);
                e
            })?;

        let mut args = FieldTable::default();
        args.insert("x-expires".into(), AMQPValue::LongUInt(3600000));

        channel
            .queue_declare(
                queue_name,
                QueueDeclareOptions {
                    passive: false,
                    durable: false,
                    exclusive: false,
                    auto_delete: true,
                    nowait: false,
                },
                args,
            )
            .await
            .map_err(|err| {
                let msg = format!("declaring queue '{}': {:?}", queue_name, err);
                tracing::error!(msg);
                msg
            })?;

        channel
            .queue_bind(
                queue_name,
                exchange_name,
                routing_key,
                QueueBindOptions::default(),
                FieldTable::default(),
            )
            .await
            .map_err(|err| {
                let msg = format!(
                    "binding queue '{}' to exchange '{}': {:?}",
                    queue_name, exchange_name, err
                );
                tracing::error!(msg);
                msg
            })?;

        let channel = self.create_channel().await?;
        Ok(channel)
    }
}
