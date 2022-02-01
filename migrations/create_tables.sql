create extension if not exists "uuid-ossp";

create table identities (
  id uuid primary key,
  state varchar (16) not null,
  email varchar (255) unique,
  groups varchar [] not null,
  inserted_at timestamp not null,
  updated_at timestamp not null
);

create index identities_email_index ON identities (email);

create table identities_data (
  id uuid primary key,
  identity_id uuid not null unique,
  public bytea not null,
  sensitive bytea not null,
  foreign key (identity_id) references identities (id) on delete cascade
);

create index identities_data_identity_id_index ON identities_data (identity_id);

create table credentials (
  id uuid primary key,
  identity_id uuid not null,
  kind varchar (16) not null,
  password_hash bytea,
  inserted_at timestamp not null,
  updated_at timestamp not null,
  unique (identity_id, kind),
  foreign key (identity_id) references identities (id) on delete cascade
);

create index credentials_identity_id_index ON credentials (identity_id);

create table verifiable_addresses (
  id uuid primary key,
  identity_id uuid not null,
  kind varchar (16) not null,
  state varchar (16) not null,
  value varchar (128) not null,
  verified bool not null,
  verified_at timestamp,
  inserted_at timestamp not null,
  updated_at timestamp not null,
  unique (identity_id, value),
  unique (kind, value),
  foreign key (identity_id) references identities (id) on delete cascade
);

create index verifiable_addresses_identity_id_index ON verifiable_addresses (identity_id);

create table tokens (
  id uuid primary key,
  identity_id uuid not null,
  verifiable_address_id uuid not null unique,
  kind varchar (16) not null,
  value varchar (32) not null,
  inserted_at timestamp not null,
  updated_at timestamp not null,
  foreign key (identity_id) references identities (id) on delete cascade,
  foreign key (verifiable_address_id) references verifiable_addresses (id) on delete cascade
);

create index tokens_identity_id_index ON tokens (identity_id);