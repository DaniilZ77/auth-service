create extension if not exists "uuid-ossp";

create table if not exists sessions (
    id uuid primary key not null default uuid_generate_v4(),
    refresh_token_hash varchar(128) not null,
    is_revoked boolean not null default false,
    user_agent varchar(256) not null,
    ip_address varchar(64) not null,
    expiry timestamp not null,
    updated_at timestamp not null default now(),
    created_at timestamp not null default now()
);