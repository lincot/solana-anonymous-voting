use actix_cors::Cors;
use actix_web::{get, web, App, HttpServer, Responder};
use openssl::ssl::{SslAcceptor, SslFiletype, SslMethod};
use serde::{Deserialize, Serialize};
use sqlx::PgPool;

use crate::config::SslConfig;

#[derive(Clone)]
struct AppState {
    pool: PgPool,
}

pub struct Server {
    pool: PgPool,
}

impl Server {
    pub fn new(pool: PgPool) -> Self {
        Self { pool }
    }

    pub async fn execute(self, ssl_config: SslConfig, workers: usize) -> std::io::Result<()> {
        let state = AppState { pool: self.pool };

        let ip = ("0.0.0.0", 8443);
        let mut ssl_builder = SslAcceptor::mozilla_intermediate(SslMethod::tls())?;
        ssl_builder.set_private_key_file(ssl_config.key, SslFiletype::PEM)?;
        ssl_builder.set_certificate_chain_file(ssl_config.cert)?;

        HttpServer::new(move || {
            App::new()
                .app_data(web::Data::new(state.clone()))
                .wrap(Cors::permissive())
                .wrap(actix_web::middleware::Compress::default())
                .service(get_poll)
                .service(list_votes)
        })
        .bind_openssl(ip, ssl_builder)?
        .workers(workers)
        .run()
        .await
    }
}

#[derive(Serialize)]
struct PollOut {
    poll_id: i64,
    n_choices: i16,
    census_root: String,
    coordinator_key: (String, String),
    voting_start_time: i64,
    voting_end_time: i64,
    fee: i64,
    platform_fee: i64,
    fee_destination: String,
    description_url: String,
    census_url: String,
    tally_finished: bool,
}

#[get("/polls/{poll_id}")]
async fn get_poll(
    state: web::Data<AppState>,
    path: web::Path<i64>,
) -> actix_web::Result<impl Responder> {
    let poll_id = path.into_inner();
    let rec = sqlx::query!(
        r#"
        SELECT poll_id, n_choices, census_root, coord_x, coord_y,
               voting_start_time, voting_end_time, fee, platform_fee,
               fee_destination, description_url, census_url, tally_finished
        FROM polls WHERE poll_id = $1
        "#,
        poll_id
    )
    .fetch_optional(&state.pool)
    .await
    .map_err(|_| actix_web::error::ErrorInternalServerError("db"))?;

    if let Some(p) = rec {
        let out = PollOut {
            poll_id: p.poll_id,
            n_choices: p.n_choices,
            census_root: hex::encode(&p.census_root),
            coordinator_key: (hex::encode(&p.coord_x), hex::encode(&p.coord_y)),
            voting_start_time: p.voting_start_time,
            voting_end_time: p.voting_end_time,
            fee: p.fee,
            platform_fee: p.platform_fee,
            fee_destination: p.fee_destination,
            description_url: p.description_url,
            census_url: p.census_url,
            tally_finished: p.tally_finished,
        };
        Ok(web::Json(out))
    } else {
        Err(actix_web::error::ErrorNotFound("poll not found"))
    }
}

#[derive(Serialize)]
struct VoteOut {
    id: i64,
    eph_x: String,
    eph_y: String,
    nonce: i64,
    ciphertext: String,
}

#[derive(Deserialize)]
struct VotesQuery {
    limit: Option<i64>,
    after_id: Option<i64>,
}

#[get("/polls/{poll_id}/votes")]
async fn list_votes(
    state: web::Data<AppState>,
    path: web::Path<i64>,
    query: web::Query<VotesQuery>,
) -> actix_web::Result<impl Responder> {
    let poll_id = path.into_inner();
    let limit = query.limit.unwrap_or(100).clamp(1, 1000);
    let after_id = query.after_id.unwrap_or(0);

    let rows = sqlx::query!(
        r#"
        SELECT id, eph_x, eph_y, nonce, ciphertext
        FROM votes
        WHERE poll_id = $1 AND id > $2
        ORDER BY id ASC
        LIMIT $3
        "#,
        poll_id,
        after_id,
        limit
    )
    .fetch_all(&state.pool)
    .await
    .map_err(|_| actix_web::error::ErrorInternalServerError("db"))?;

    let mut next_after_id = None;
    let items: Vec<_> = rows
        .into_iter()
        .map(|r| {
            next_after_id = Some(r.id);
            VoteOut {
                id: r.id,
                eph_x: hex::encode(&r.eph_x),
                eph_y: hex::encode(&r.eph_y),
                nonce: r.nonce,
                ciphertext: hex::encode(&r.ciphertext),
            }
        })
        .collect();

    #[derive(Serialize)]
    struct Page {
        items: Vec<VoteOut>,
        next_after_id: Option<i64>,
    }

    Ok(web::Json(Page {
        items,
        next_after_id,
    }))
}
