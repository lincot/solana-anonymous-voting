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
                .service(polls_by_voter)
                .service(polls_by_coordinator)
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
    title: String,
    choices: Vec<String>,
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
        SELECT poll_id, title, choices, census_root, coord_x, coord_y,
               voting_start_time, voting_end_time, fee, platform_fee,
               fee_destination, description_url, census_url, tally_finished
        FROM polls WHERE poll_id = $1 AND title IS NOT NULL AND census_valid IS TRUE
        "#,
        poll_id
    )
    .fetch_optional(&state.pool)
    .await
    .map_err(|_| actix_web::error::ErrorInternalServerError("db"))?;

    if let Some(p) = rec {
        let out = PollOut {
            poll_id: p.poll_id,
            title: p
                .title
                .expect("title expected to be not null as per query constraint"),
            choices: p
                .choices
                .expect("choices are expected to be set atomically with title"),
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
    after: Option<i64>,
}

#[get("/polls/{poll_id}/votes")]
async fn list_votes(
    state: web::Data<AppState>,
    path: web::Path<i64>,
    query: web::Query<VotesQuery>,
) -> actix_web::Result<impl Responder> {
    let poll_id = path.into_inner();
    let limit = query.limit.unwrap_or(100).clamp(1, 1000);
    let after_id = query.after.unwrap_or(0);

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
        limit + 1
    )
    .fetch_all(&state.pool)
    .await
    .map_err(|_| actix_web::error::ErrorInternalServerError("db"))?;

    let next_after = if rows.len() > limit as usize {
        Some(rows[limit as usize - 1].id)
    } else {
        None
    };

    let items: Vec<_> = rows
        .into_iter()
        .take(limit as usize)
        .map(|r| VoteOut {
            id: r.id,
            eph_x: hex::encode(&r.eph_x),
            eph_y: hex::encode(&r.eph_y),
            nonce: r.nonce,
            ciphertext: hex::encode(&r.ciphertext),
        })
        .collect();

    #[derive(Serialize)]
    struct Page {
        items: Vec<VoteOut>,
        next_after: Option<i64>,
    }

    Ok(web::Json(Page { items, next_after }))
}

#[derive(Serialize)]
struct PollItem {
    poll_id: i64,
    voting_start_time: i64,
    voting_end_time: i64,
    title: String,
    choices: Vec<String>,
}

#[derive(Serialize)]
struct PollPage {
    items: Vec<PollItem>,
    next_after: Option<i64>,
}

#[derive(Deserialize)]
struct UserPollsQuery {
    limit: Option<i64>,
    after: Option<i64>,
}

#[actix_web::get("/voters/{leaf}/polls")]
async fn polls_by_voter(
    state: web::Data<AppState>,
    leaf: web::Path<String>,
    q: web::Query<UserPollsQuery>,
) -> actix_web::Result<impl Responder> {
    let mut leaf_arr = [0u8; 32];
    hex::decode_to_slice(&*leaf, &mut leaf_arr)
        .map_err(|_| actix_web::error::ErrorBadRequest("bad hex"))?;
    let limit = q.limit.unwrap_or(50).clamp(1, 500);
    let after = q.after.unwrap_or(0);

    let rows = sqlx::query!(
        r#"
        SELECT p.poll_id, p.title, p.choices, p.voting_start_time,
               p.voting_end_time, p.description_url, p.census_url
        FROM voter_polls vp
        JOIN polls p ON p.poll_id = vp.poll_id
            AND census_valid = TRUE AND title IS NOT NULL
        WHERE vp.key_hash = $1 AND p.poll_id > $2
        ORDER BY p.poll_id ASC
        LIMIT $3
        "#,
        &leaf_arr,
        after,
        limit + 1
    )
    .fetch_all(&state.pool)
    .await
    .map_err(|_| actix_web::error::ErrorInternalServerError("db"))?;

    let next_after = if rows.len() > limit as usize {
        Some(rows[limit as usize - 1].poll_id)
    } else {
        None
    };

    let items = rows
        .into_iter()
        .take(limit as usize)
        .map(|r| PollItem {
            poll_id: r.poll_id,
            voting_start_time: r.voting_start_time,
            voting_end_time: r.voting_end_time,
            title: r
                .title
                .expect("title expected to be not null as per query constraint"),
            choices: r
                .choices
                .expect("choices are expected to be set atomically with title"),
        })
        .collect();

    Ok(web::Json(PollPage { items, next_after }))
}

#[actix_web::get("/coordinators/{xy}/polls")]
async fn polls_by_coordinator(
    state: web::Data<AppState>,
    path: web::Path<String>,
    q: web::Query<UserPollsQuery>,
) -> actix_web::Result<impl Responder> {
    let mut xy_arr = [0u8; 64];
    hex::decode_to_slice(&*path, &mut xy_arr)
        .map_err(|_| actix_web::error::ErrorBadRequest("bad hex"))?;
    let limit = q.limit.unwrap_or(50).clamp(1, 500);
    let after = q.after.unwrap_or(0);

    let rows = sqlx::query!(
        r#"
        SELECT poll_id, title, choices, voting_start_time, voting_end_time,
               description_url, census_url
        FROM polls
        WHERE coord_x=$1 AND coord_y=$2 AND poll_id > $3 AND census_valid = TRUE
            AND title IS NOT NULL
        ORDER BY poll_id ASC
        LIMIT $4
        "#,
        &xy_arr[..32],
        &xy_arr[32..],
        after,
        limit + 1
    )
    .fetch_all(&state.pool)
    .await
    .map_err(|_| actix_web::error::ErrorInternalServerError("db"))?;

    let next_after = if rows.len() > limit as usize {
        Some(rows[limit as usize - 1].poll_id)
    } else {
        None
    };

    let items = rows
        .into_iter()
        .take(limit as usize)
        .map(|r| PollItem {
            poll_id: r.poll_id,
            voting_start_time: r.voting_start_time,
            voting_end_time: r.voting_end_time,
            title: r
                .title
                .expect("title expected to be not null as per query constraint"),
            choices: r
                .choices
                .expect("choices are expected to be set atomically with title"),
        })
        .collect();

    Ok(web::Json(PollPage { items, next_after }))
}
