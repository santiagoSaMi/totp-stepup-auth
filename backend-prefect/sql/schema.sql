-- Schema for the 2FA lab. Run once in the Supabase SQL editor.
--
-- The backend connects with the Postgres connection string (role `postgres`),
-- which bypasses Row Level Security. RLS is enabled with no policies so that
-- Supabase's public REST API (anon key) cannot read password hashes or secrets.

create type mfa_status as enum ('DISABLED', 'PENDING_VERIFICATION', 'ACTIVE');

create table users (
    id            uuid primary key default gen_random_uuid(),
    username      text not null unique check (username = lower(username)),
    password_hash text not null,
    created_at    timestamptz not null default now()
);

-- One row per user once they start enrolling. No row means DISABLED.
-- The TOTP secret can't be hashed (the server needs it to compute codes), so it
-- is stored encrypted with AES-256-GCM by the backend: "v1:<nonce>:<ciphertext>".
-- The key lives in the backend's .env, never in the database.
create table mfa_configs (
    user_id          uuid primary key references users (id) on delete cascade,
    secret_encrypted text,
    status           mfa_status not null default 'DISABLED',
    created_at       timestamptz not null default now(),
    updated_at       timestamptz not null default now(),
    activated_at     timestamptz,

    constraint secret_required_when_enabled
        check (status = 'DISABLED' or secret_encrypted is not null),
    constraint activated_at_when_active
        check (status <> 'ACTIVE' or activated_at is not null),
    constraint secret_is_encrypted
        check (secret_encrypted is null or secret_encrypted like 'v1:%')
);

-- Single-use emergency codes. Only the SHA-256 hash is stored.
create table backup_codes (
    id         uuid primary key default gen_random_uuid(),
    user_id    uuid not null references users (id) on delete cascade,
    code_hash  text not null,
    used_at    timestamptz,
    created_at timestamptz not null default now(),

    unique (user_id, code_hash)
);

alter table users        enable row level security;
alter table mfa_configs  enable row level security;
alter table backup_codes enable row level security;
