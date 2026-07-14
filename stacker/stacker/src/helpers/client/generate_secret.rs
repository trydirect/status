use crate::helpers::client;
use rand::Rng;
use sqlx::PgPool;

fn make_secret(len: usize) -> String {
    const CHARSET: &[u8] =
        b"ABCDEFGHIJKLMNOPQRSTUVWXYZabcdefghijklmnopqrstuvwxyz0123456789)(*&^%$#@!~";
    let mut rng = rand::thread_rng();

    (0..len)
        .map(|_| {
            let idx = rng.gen_range(0..CHARSET.len());
            CHARSET[idx] as char
        })
        .collect()
}

pub async fn generate_secret(pool: &PgPool, len: usize) -> Result<String, String> {
    loop {
        let secret = make_secret(len);
        match client::is_secret_unique(pool, &secret).await {
            Ok(is_unique) if is_unique => {
                return Ok(secret);
            }
            Ok(_) => {
                continue;
            }
            Err(e) => {
                return Err(format!("Failed to execute query: {:?}", e));
            }
        }
    }
}
