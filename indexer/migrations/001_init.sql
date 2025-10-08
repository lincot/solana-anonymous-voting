CREATE TABLE polls (
  poll_id           BIGINT PRIMARY KEY,
  n_choices         SMALLINT NOT NULL,
  census_root       BYTEA NOT NULL,  -- 32
  coord_x           BYTEA NOT NULL,  -- 32
  coord_y           BYTEA NOT NULL,  -- 32
  voting_start_time BIGINT NOT NULL, -- u64
  voting_end_time   BIGINT NOT NULL, -- u64
  fee               BIGINT NOT NULL,
  platform_fee      BIGINT NOT NULL,
  fee_destination   TEXT NOT NULL,
  description_url   TEXT NOT NULL,
  census_url        TEXT NOT NULL,
  tally_finished    BOOLEAN NOT NULL DEFAULT FALSE
);

CREATE TABLE votes (
  id BIGSERIAL PRIMARY KEY,
  -- msg_hash   BYTEA  PRIMARY KEY, -- 32
  poll_id    BIGINT NOT NULL REFERENCES polls(poll_id) ON DELETE CASCADE,
  eph_x      BYTEA  NOT NULL, -- 32
  eph_y      BYTEA  NOT NULL, -- 32
  nonce      BIGINT NOT NULL, -- u64
  ciphertext BYTEA  NOT NULL -- 7*32 = 224
);

CREATE TABLE cursors (
  stream TEXT PRIMARY KEY,
  last_sig  TEXT   NOT NULL
);

CREATE INDEX votes_poll_id_id_idx ON votes (poll_id, id);
