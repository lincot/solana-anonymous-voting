use bytes::BytesMut;
use core::time::Duration;
use futures_util::StreamExt;
use serde::Deserialize;
use sqlx::PgPool;
use thiserror::Error;
use tokio::sync::mpsc::UnboundedReceiver;
use tokio_stream::wrappers::UnboundedReceiverStream;
use tracing::{error, info};

const MAX_TITLE_LEN: usize = 100;
const MAX_CHOICES: usize = 8;
const MAX_CHOICE_LEN: usize = 100;

#[derive(Debug, Clone)]
pub struct DescriptionCmd {
    pub poll_id: i64,
    pub url: String,
    pub n_choices: u8,
}

#[derive(Debug, Error)]
enum DescriptionError {
    #[error("sqlx: {0}")]
    Sqlx(#[from] sqlx::Error),
    #[error("http: {0}")]
    Http(#[from] reqwest::Error),
    #[error("json: {0}")]
    Json(#[from] serde_json::Error),
}

pub struct DescriptionManager {
    pg_pool: PgPool,
    reqwest_client: reqwest::Client,
    desc_receiver: UnboundedReceiver<DescriptionCmd>,
    max_concurrency: usize,
}

impl DescriptionManager {
    pub fn new(
        pg_pool: PgPool,
        http: reqwest::Client,
        rx: UnboundedReceiver<DescriptionCmd>,
        max_concurrency: usize,
    ) -> Self {
        Self {
            pg_pool,
            reqwest_client: http,
            desc_receiver: rx,
            max_concurrency,
        }
    }

    pub async fn execute(self) {
        UnboundedReceiverStream::new(self.desc_receiver)
            .for_each_concurrent(self.max_concurrency, move |cmd| {
                let pool = self.pg_pool.clone();
                let client = self.reqwest_client.clone();
                async move {
                    if let Err(err) =
                        Self::ingest(&pool, &client, cmd.poll_id, cmd.url, cmd.n_choices).await
                    {
                        error!("description ingest failed for poll {}: {err}", cmd.poll_id);
                    } else {
                        info!("description cached for poll {}", cmd.poll_id);
                    }
                }
            })
            .await;
    }

    async fn ingest(
        pool: &PgPool,
        http: &reqwest::Client,
        poll_id: i64,
        url: String,
        n_choices: u8,
    ) -> Result<(), DescriptionError> {
        if sqlx::query("SELECT FROM polls WHERE poll_id=$1 AND TITLE IS NOT NULL")
            .bind(poll_id)
            .fetch_optional(pool)
            .await?
            .is_some()
        {
            return Ok(());
        }

        const BYTES_LIMIT: usize = 64 * 1024;
        let resp = http
            .get(&url)
            .timeout(Duration::from_secs(30))
            .send()
            .await?
            .error_for_status()?;

        if let Some(len) = resp.content_length() {
            if len as usize > BYTES_LIMIT {
                Self::mark_bad(pool, poll_id, "description too large").await?;
                return Ok(());
            }
        }

        let mut body = BytesMut::new();
        let mut stream = resp.bytes_stream();
        // TODO does stream honor timeout?
        while let Some(chunk) = stream.next().await {
            let chunk = chunk?;
            if body.len() + chunk.len() > BYTES_LIMIT {
                return Self::mark_bad(pool, poll_id, "description too large (>64KiB)")
                    .await
                    .map_err(DescriptionError::from);
            }
            body.extend_from_slice(&chunk);
        }

        #[derive(Deserialize)]
        struct Desc {
            title: String,
            choices: Vec<String>,
        }

        let desc: Desc = serde_json::from_slice(&body)?;
        let (title, mut choices) = (desc.title.trim().to_string(), desc.choices);

        if title.is_empty() || title.chars().count() > MAX_TITLE_LEN {
            return Self::mark_bad(pool, poll_id, "invalid title length")
                .await
                .map_err(DescriptionError::from);
        }

        if choices.is_empty() || choices.len() > MAX_CHOICES {
            return Self::mark_bad(pool, poll_id, "invalid choices count")
                .await
                .map_err(DescriptionError::from);
        }

        if choices.len() != n_choices as usize {
            return Self::mark_bad(pool, poll_id, "choices count != n_choices")
                .await
                .map_err(DescriptionError::from);
        }

        for c in &mut choices {
            *c = c.trim().to_string();
            if c.is_empty() || c.chars().count() > MAX_CHOICE_LEN {
                return Self::mark_bad(pool, poll_id, "choice length invalid")
                    .await
                    .map_err(DescriptionError::from);
            }
        }

        sqlx::query!(
            r#"UPDATE polls SET title=$2, choices=$3 WHERE poll_id=$1"#,
            poll_id,
            title,
            &choices
        )
        .execute(pool)
        .await?;

        Ok(())
    }

    async fn mark_bad(pool: &PgPool, poll_id: i64, reason: &str) -> Result<(), sqlx::Error> {
        sqlx::query!(
            "UPDATE polls SET description_invalid_reason=$2 WHERE poll_id=$1",
            poll_id,
            reason
        )
        .execute(pool)
        .await?;
        Ok(())
    }

    pub async fn enqueue_unfinished(
        pg_pool: &PgPool,
        tx: &tokio::sync::mpsc::UnboundedSender<DescriptionCmd>,
    ) -> Result<(), sqlx::Error> {
        let rows = sqlx::query!(
            r#"
            SELECT p.poll_id, p.description_url, p.n_choices
            FROM polls p
            WHERE p.title IS NULL
            "#
        )
        .fetch_all(pg_pool)
        .await?;

        for r in rows {
            tx.send(DescriptionCmd {
                poll_id: r.poll_id,
                url: r.description_url,
                n_choices: r.n_choices as u8,
            })
            .unwrap();
        }

        Ok(())
    }
}
