use crate::forms::project::DockerImage;
use crate::helpers::dockerhub::DockerHub;
use actix_web::{rt, Result};

use tracing_subscriber::FmtSubscriber;

pub struct DockerhubCommand {
    json: String,
}

impl DockerhubCommand {
    pub fn new(json: String) -> Self {
        Self { json }
    }
}

impl crate::console::commands::CallableTrait for DockerhubCommand {
    fn call(&self) -> Result<(), Box<dyn std::error::Error>> {
        let subscriber = FmtSubscriber::builder()
            .with_max_level(tracing::Level::DEBUG)
            .finish();
        tracing::subscriber::set_global_default(subscriber)
            .expect("setting default subscriber failed");

        rt::System::new().block_on(async {
            println!("{}", self.json);
            let docker_image: DockerImage = serde_json::from_str(&self.json)?;
            let dockerhub = DockerHub::try_from(&docker_image)?;
            let is_active = dockerhub.is_active().await?;

            println!("image is active: {is_active}");

            Ok(())
        })
    }
}
