use bytes::BytesMut;
use core::{fmt::Write, time::Duration};
use futures_util::StreamExt;
use sqlx::{Arguments, PgPool};
use thiserror::Error;
use tokio::sync::mpsc::{UnboundedReceiver, UnboundedSender};
use tokio_stream::wrappers::UnboundedReceiverStream;

#[derive(Debug, Clone)]
pub struct CensusCmd {
    pub poll_id: i64,
    pub url: String,
    pub expected_voters: u64,
}

#[derive(Debug, Error)]
enum CensusManagerError {
    #[error("Sqlx error {0}")]
    Sqlx(#[from] sqlx::Error),
    #[error("Failed to add sqlx arguments")]
    SqlxArgs,
    #[error("HTTP error {0}")]
    Http(#[from] reqwest::Error),
}

pub struct CensusManager {
    pg_pool: PgPool,
    reqwest_client: reqwest::Client,
    cmd_receiver: UnboundedReceiver<CensusCmd>,
    max_concurrency: usize,
}

impl CensusManager {
    pub fn new(
        pg_pool: PgPool,
        reqwest_client: reqwest::Client,
        cmd_receiver: UnboundedReceiver<CensusCmd>,
        max_concurrency: usize,
    ) -> Self {
        Self {
            pg_pool,
            reqwest_client,
            cmd_receiver,
            max_concurrency,
        }
    }

    pub async fn execute(self) {
        UnboundedReceiverStream::new(self.cmd_receiver)
            .for_each_concurrent(self.max_concurrency, move |cmd| {
                let pg_pool = self.pg_pool.clone();
                let reqwest_client = self.reqwest_client.clone();
                async move {
                    if let Err(err) = Self::ingest(
                        &pg_pool,
                        &reqwest_client,
                        cmd.poll_id,
                        cmd.url,
                        cmd.expected_voters,
                    )
                    .await
                    {
                        tracing::error!("census ingest failed for poll {}: {}", cmd.poll_id, err);
                    } else {
                        tracing::info!("ingested census for poll {}", cmd.poll_id);
                    }
                }
            })
            .await;
    }

    async fn ingest(
        pg_pool: &PgPool,
        reqwest_client: &reqwest::Client,
        poll_id: i64,
        url: String,
        expected_voters: u64,
    ) -> Result<(), CensusManagerError> {
        if matches!(
            sqlx::query_scalar!("SELECT census_valid FROM polls WHERE poll_id=$1", poll_id)
                .fetch_optional(pg_pool)
                .await?,
            Some(Some(true))
        ) {
            return Ok(());
        }

        let resp = reqwest_client
            .get(&url)
            .timeout(Duration::from_secs(30))
            .send()
            .await?
            .error_for_status()?;

        if let Some(content_length) = resp.content_length() {
            if content_length % 32 != 0 {
                Self::mark_bad(pg_pool, poll_id, "census size not divisible by 32").await?;
            }
            let total = content_length / 32;
            if total != expected_voters {
                Self::mark_bad(
                    pg_pool,
                    poll_id,
                    &format!("expected {}, got {}", expected_voters, total),
                )
                .await?;
            }
        }

        let mut stream = resp.bytes_stream();
        let mut buf = BytesMut::new();
        let mut batch: Vec<[u8; 32]> = Vec::with_capacity(10_000);
        let mut total: u64 = 0;

        // TODO does stream honor timeout?
        while let Some(chunk) = stream.next().await {
            let chunk = chunk?;
            buf.extend_from_slice(&chunk);
            if total + buf.len() as u64 / 32 > expected_voters {
                Self::mark_bad(pg_pool, poll_id, "too many voters").await?;
                return Ok(());
            }
            while buf.len() >= 32 {
                let mut leaf = [0u8; 32];
                leaf.copy_from_slice(&buf.split_to(32));
                batch.push(leaf);
                if batch.len() >= 10_000 {
                    Self::insert_leaves_batch(pg_pool, poll_id, &batch).await?;
                    total += batch.len() as u64;
                    batch.clear();
                }
            }
        }

        if !buf.is_empty() {
            Self::mark_bad(pg_pool, poll_id, "census size not divisible by 32").await?;
            return Ok(());
        }
        if !batch.is_empty() {
            Self::insert_leaves_batch(pg_pool, poll_id, &batch).await?;
            total += batch.len() as u64;
        }

        if total != expected_voters {
            Self::mark_bad(
                pg_pool,
                poll_id,
                &format!("expected {}, got {}", expected_voters, total),
            )
            .await?;
            return Ok(());
        }

        sqlx::query!(
            r#"UPDATE polls SET census_valid=TRUE WHERE poll_id=$1"#,
            poll_id
        )
        .execute(pg_pool)
        .await?;

        Ok(())
    }

    async fn mark_bad(pg_pool: &PgPool, poll_id: i64, reason: &str) -> sqlx::Result<()> {
        sqlx::query!(
            "UPDATE polls SET census_valid=FALSE, census_invalid_reason=$2 WHERE poll_id=$1",
            poll_id,
            reason
        )
        .execute(pg_pool)
        .await?;
        Ok(())
    }

    async fn insert_leaves_batch(
        pg_pool: &PgPool,
        poll_id: i64,
        leaves: &[[u8; 32]],
    ) -> Result<(), CensusManagerError> {
        let mut sql = String::from("INSERT INTO voter_polls (poll_id, key_hash) VALUES ");
        let mut args = sqlx::postgres::PgArguments::default();
        for (i, leaf) in leaves.iter().enumerate() {
            if i > 0 {
                sql.push(',');
            }
            let p1 = 2 * i + 1;
            let p2 = 2 * i + 2;
            write!(&mut sql, "(${p1}, ${p2})").unwrap();
            args.add(poll_id)
                .map_err(|_| CensusManagerError::SqlxArgs)?;
            args.add(&leaf[..])
                .map_err(|_| CensusManagerError::SqlxArgs)?;
        }
        sql.push_str(" ON CONFLICT DO NOTHING");
        sqlx::query_with(&sql, args).execute(pg_pool).await?;
        Ok(())
    }

    pub(crate) async fn enqueue_unfinished(
        pool: &PgPool,
        census_sender: &UnboundedSender<CensusCmd>,
    ) -> sqlx::Result<()> {
        let rows = sqlx::query!(
            r#"
        SELECT poll_id, census_url, expected_voters
        FROM polls
        WHERE census_valid IS NULL OR census_valid = FALSE
        "#
        )
        .fetch_all(pool)
        .await?;

        for row in rows {
            let cmd = CensusCmd {
                poll_id: row.poll_id,
                url: row.census_url,
                expected_voters: row.expected_voters as u64,
            };
            census_sender.send(cmd).unwrap();
        }
        Ok(())
    }
}
