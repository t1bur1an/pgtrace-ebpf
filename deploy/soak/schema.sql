DROP TABLE IF EXISTS soak_docs;
CREATE TABLE soak_docs (
    id         bigserial PRIMARY KEY,
    tenant     int         NOT NULL,
    payload    jsonb       NOT NULL,
    tags       text[]      NOT NULL DEFAULT '{}',
    body       text        NOT NULL DEFAULT '',
    updated_at timestamptz NOT NULL DEFAULT now()
);
CREATE INDEX soak_docs_tenant ON soak_docs (tenant, id);
CREATE INDEX soak_docs_payload ON soak_docs USING gin (payload jsonb_path_ops);
