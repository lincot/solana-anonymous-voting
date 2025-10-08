use anon_vote::events::{CreatePollEvent, FinishTallyEvent, VoteEvent};
use core::mem::transmute;
use sqlx::{postgres::PgQueryResult, PgPool, Postgres, Transaction};
use tokio::sync::mpsc::UnboundedReceiver;
use tracing::info;

use crate::IndexerEvent;

pub struct DbManager {
    pool: PgPool,
    event_receiver: UnboundedReceiver<(String, Vec<IndexerEvent>)>,
}

impl DbManager {
    pub async fn new(
        pool: PgPool,
        event_receiver: UnboundedReceiver<(String, Vec<IndexerEvent>)>,
    ) -> sqlx::Result<Self> {
        Ok(Self {
            pool,
            event_receiver,
        })
    }

    pub async fn get_cursor(&self) -> sqlx::Result<Option<String>> {
        let row = sqlx::query!(
            r#"SELECT last_sig FROM cursors WHERE stream = $1"#,
            "confirmed"
        )
        .fetch_optional(&self.pool)
        .await?;
        Ok(row.map(|r| r.last_sig))
    }

    pub async fn execute(&mut self) -> sqlx::Result<()> {
        while let Some((signature, events)) = self.event_receiver.recv().await {
            info!("Processed events {events:?}");
            let mut tx = self.pool.begin().await?;

            for event in events {
                Self::on_event(&mut tx, event).await?;
            }
            Self::upsert_cursor(&mut tx, &signature).await?;
            tx.commit().await?;
        }

        Ok(())
    }

    async fn upsert_cursor(
        tx: &mut Transaction<'_, Postgres>,
        last_sig: &str,
    ) -> sqlx::Result<PgQueryResult> {
        sqlx::query!(
            r#"
        INSERT INTO cursors (stream, last_sig)
        VALUES ($1, $2)
        ON CONFLICT (stream) DO UPDATE
        SET last_sig = EXCLUDED.last_sig
        WHERE cursors.last_sig <> EXCLUDED.last_sig
        "#,
            "confirmed",
            last_sig
        )
        .execute(&mut **tx)
        .await
    }

    async fn on_event(
        tx: &mut Transaction<'_, Postgres>,
        event: IndexerEvent,
    ) -> sqlx::Result<PgQueryResult> {
        match event {
            IndexerEvent::CreatePoll(event) => Self::on_create_poll(tx, event).await,
            IndexerEvent::Vote(event) => Self::on_vote(tx, event).await,
            IndexerEvent::FinishTally(event) => Self::on_finish_tally(tx, event).await,
        }
    }

    async fn on_create_poll(
        tx: &mut Transaction<'_, Postgres>,
        e: CreatePollEvent,
    ) -> sqlx::Result<PgQueryResult> {
        sqlx::query!(
            r#"
        INSERT INTO polls (
          poll_id, n_choices, census_root, coord_x, coord_y,
          voting_start_time, voting_end_time, fee, platform_fee, fee_destination,
          description_url, census_url
        )
        VALUES ($1,$2,$3,$4,$5,$6,$7,$8,$9,$10,$11,$12)
        ON CONFLICT (poll_id) DO NOTHING
        "#,
            e.poll_id as i64,
            e.n_choices as i16,
            &e.census_root[..],
            &e.coordinator_key.x[..],
            &e.coordinator_key.y[..],
            e.voting_start_time as i64,
            e.voting_end_time as i64,
            e.fee as i64,
            e.platform_fee as i64,
            e.fee_destination.to_string(),
            e.description_url,
            e.census_url
        )
        .execute(&mut **tx)
        .await
    }

    async fn on_vote(
        tx: &mut Transaction<'_, Postgres>,
        e: VoteEvent,
    ) -> sqlx::Result<PgQueryResult> {
        sqlx::query!(
            r#"
        INSERT INTO votes (
          poll_id, eph_x, eph_y, nonce, ciphertext
        )
        VALUES ($1,$2,$3,$4,$5)
        "#,
            e.poll_id as i64,
            &e.eph_key.x[..],
            &e.eph_key.y[..],
            e.nonce as i64,
            &unsafe { transmute::<[[u8; 32]; 7], [u8; 224]>(e.ciphertext) },
        )
        .execute(&mut **tx)
        .await
    }

    async fn on_finish_tally(
        tx: &mut Transaction<'_, Postgres>,
        e: FinishTallyEvent,
    ) -> sqlx::Result<PgQueryResult> {
        sqlx::query!(
            r#"
        UPDATE polls
        SET tally_finished = TRUE
        WHERE poll_id = $1
        "#,
            e.poll_id as i64,
        )
        .execute(&mut **tx)
        .await?;

        sqlx::query!("DELETE FROM votes WHERE poll_id = $1", e.poll_id as i64)
            .execute(&mut **tx)
            .await
    }
}
