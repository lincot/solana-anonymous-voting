CREATE TABLE polls (
  id                         BIGSERIAL PRIMARY KEY,
  poll_id                    BIGINT UNIQUE NOT NULL,
  title                      VARCHAR(100),
  choices                    VARCHAR(100)[],
  n_choices                  SMALLINT NOT NULL,
  census_root                BYTEA NOT NULL,  -- 32
  coord_x                    BYTEA NOT NULL,  -- 32
  coord_y                    BYTEA NOT NULL,  -- 32
  voting_start_time          BIGINT NOT NULL, -- u64
  voting_end_time            BIGINT NOT NULL, -- u64
  fee                        BIGINT NOT NULL,
  platform_fee               BIGINT NOT NULL,
  fee_destination            TEXT NOT NULL,
  description_url            TEXT NOT NULL,
  census_url                 TEXT NOT NULL,
  tally                      BIGINT[],
  census_valid               BOOLEAN,
  census_invalid_reason      TEXT,
  expected_voters            BIGINT NOT NULL,
  description_invalid_reason TEXT

  CONSTRAINT choices_count CHECK (array_length(choices, 1) BETWEEN 1 AND 8)
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

CREATE INDEX votes_poll_id_id_idx ON votes (poll_id, id);

CREATE TABLE voter_polls (
  poll_id  BIGINT NOT NULL REFERENCES polls(poll_id) ON DELETE CASCADE,
  key_hash BYTEA  NOT NULL,
  PRIMARY KEY (poll_id, key_hash)
);

CREATE INDEX voter_polls_key_hash_idx ON voter_polls (key_hash);
CREATE INDEX polls_coord_idx ON polls (coord_x, coord_y);

CREATE TABLE cursors (
  stream TEXT PRIMARY KEY,
  last_sig  TEXT   NOT NULL
);
