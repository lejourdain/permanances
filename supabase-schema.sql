-- =====================================================================
-- Authentification par compte (NOM + MOT DE PASSE) — base durcie
-- "Gestion des Permanences" — Supabase -> SQL Editor -> coller -> Run.
-- Script idempotent (ré-exécutable sans risque).
--
--   - Inscription : un compte = pseudo (identifiant) + mot de passe.
--   - Mot de passe HACHÉ en bcrypt (algorithme lent, anti-forçage) ; jamais
--     stocké en clair ; sel intégré au hachage.
--   - Vérifié côté serveur à CHAQUE opération de données.
--   - Intégrité du JSON validée ; tables inaccessibles directement ;
--     aucune injection SQL possible.
-- =====================================================================

create schema if not exists extensions;
create extension if not exists pgcrypto with schema extensions;  -- crypt(), gen_salt()

-- ---------- COMPTES ----------
create table if not exists public.app_users (
  pseudo      text        primary key,            -- normalisé en minuscules
  pwd_hash    text        not null,               -- bcrypt ($2a$...)
  created_at  timestamptz not null default now()
);
alter table public.app_users enable row level security;   -- aucune policy => inaccessible

-- ---------- PLANNING PARTAGÉ (document unique) ----------
create table if not exists public.services (
  code        text        primary key,
  data        jsonb       not null default '{}'::jsonb,
  updated_at  timestamptz not null default now()
);
alter table public.services enable row level security;

do $$
begin
  if not exists (select 1 from pg_constraint where conname='services_data_object') then
    alter table public.services add constraint services_data_object check (jsonb_typeof(data)='object');
  end if;
  if not exists (select 1 from pg_constraint where conname='services_data_size') then
    alter table public.services add constraint services_data_size check (length(data::text) <= 4194304);
  end if;
end $$;

-- ---------- VALIDATION D'INTÉGRITÉ ----------
create or replace function public.is_valid_service_data(d jsonb)
returns boolean language sql immutable set search_path = '' as $$
  select jsonb_typeof(d)='object'
    and coalesce(jsonb_typeof(d->'agents'),'array')='array'
    and coalesce(jsonb_typeof(d->'events'),'array')='array'
    and coalesce(jsonb_typeof(d->'missions'),'array')='array'
    and coalesce(jsonb_typeof(d->'missionTypes'),'array')='array'
    and coalesce(jsonb_typeof(d->'colors'),'object')='object'
    and coalesce(jsonb_typeof(d->'slots'),'object')='object';
$$;

-- ---------- VÉRIFICATION D'IDENTIFIANTS (bcrypt, interne) ----------
create or replace function public.auth_ok(p_pseudo text, p_password text)
returns boolean language plpgsql security definer set search_path = '' as $$
declare v_hash text;
begin
  select pwd_hash into v_hash from public.app_users where pseudo = lower(btrim(p_pseudo));
  if v_hash is null then return false; end if;
  return v_hash = extensions.crypt(p_password, v_hash);
end; $$;

-- ---------- INSCRIPTION ----------
create or replace function public.auth_register(p_pseudo text, p_password text)
returns text language plpgsql security definer set search_path = '' as $$
declare v_p text := lower(btrim(p_pseudo));
begin
  if char_length(v_p) < 2 then raise exception 'PSEUDO_INVALIDE' using errcode='22023'; end if;
  if char_length(p_password) < 4 then raise exception 'MDP_TROP_COURT' using errcode='22023'; end if;
  if exists (select 1 from public.app_users where pseudo = v_p) then
    raise exception 'PSEUDO_EXISTANT' using errcode='23505';
  end if;
  insert into public.app_users(pseudo, pwd_hash)
    values (v_p, extensions.crypt(p_password, extensions.gen_salt('bf', 10)));   -- bcrypt coût 10
  return 'created';
end; $$;

-- ---------- CONNEXION : 'ok' / 'wrong' / 'new' ----------
create or replace function public.auth_check(p_pseudo text, p_password text)
returns text language plpgsql security definer set search_path = '' as $$
declare v_hash text;
begin
  select pwd_hash into v_hash from public.app_users where pseudo = lower(btrim(p_pseudo));
  if v_hash is null then return 'new'; end if;
  if v_hash = extensions.crypt(p_password, v_hash) then return 'ok'; else return 'wrong'; end if;
end; $$;

-- ---------- CHANGER LE MOT DE PASSE ----------
create or replace function public.auth_set_password(p_pseudo text, p_old text, p_new text)
returns text language plpgsql security definer set search_path = '' as $$
begin
  if not public.auth_ok(p_pseudo, p_old) then raise exception 'MOT_DE_PASSE_INCORRECT' using errcode='28000'; end if;
  if char_length(p_new) < 4 then raise exception 'MDP_TROP_COURT' using errcode='22023'; end if;
  update public.app_users
    set pwd_hash = extensions.crypt(p_new, extensions.gen_salt('bf', 10))
    where pseudo = lower(btrim(p_pseudo));
  return 'changed';
end; $$;

-- ---------- DONNÉES (auth obligatoire + intégrité) ----------
create or replace function public.service_pull(p_pseudo text, p_password text)
returns jsonb language plpgsql security definer set search_path = '' as $$
begin
  if not public.auth_ok(p_pseudo, p_password) then raise exception 'AUTH' using errcode='28000'; end if;
  return (select data from public.services where code = 'shared-service-main');
end; $$;

create or replace function public.service_when(p_pseudo text, p_password text)
returns timestamptz language plpgsql security definer set search_path = '' as $$
begin
  if not public.auth_ok(p_pseudo, p_password) then raise exception 'AUTH' using errcode='28000'; end if;
  return (select updated_at from public.services where code = 'shared-service-main');
end; $$;

create or replace function public.service_push(p_pseudo text, p_password text, p_data jsonb)
returns timestamptz language plpgsql security definer set search_path = '' as $$
declare v_now timestamptz := now();
begin
  if not public.auth_ok(p_pseudo, p_password) then raise exception 'AUTH' using errcode='28000'; end if;
  if not public.is_valid_service_data(p_data) then raise exception 'DONNEES_INVALIDES' using errcode='22023'; end if;
  if length(p_data::text) > 4194304 then raise exception 'TROP_VOLUMINEUX' using errcode='54000'; end if;
  insert into public.services(code, data, updated_at)
    values ('shared-service-main', p_data, v_now)
    on conflict (code) do update set data = excluded.data, updated_at = v_now;
  return v_now;
end; $$;

-- ---------- NETTOYAGE d'éventuelles anciennes versions ----------
drop function if exists public.service_load(text);
drop function if exists public.service_save(text, jsonb);
drop function if exists public.service_meta(text);
drop function if exists public.service_save_guarded(text, jsonb, timestamptz);
drop function if exists public.hash_sha256(text, text);

-- ---------- MOINDRE PRIVILÈGE ----------
revoke all on function public.auth_ok(text,text)                 from public;
revoke all on function public.auth_register(text,text)           from public;
revoke all on function public.auth_check(text,text)              from public;
revoke all on function public.auth_set_password(text,text,text)  from public;
revoke all on function public.service_pull(text,text)            from public;
revoke all on function public.service_when(text,text)            from public;
revoke all on function public.service_push(text,text,jsonb)      from public;
revoke all on function public.is_valid_service_data(jsonb)       from public;

grant execute on function public.auth_register(text,text)          to anon, authenticated;
grant execute on function public.auth_check(text,text)             to anon, authenticated;
grant execute on function public.auth_set_password(text,text,text) to anon, authenticated;
grant execute on function public.service_pull(text,text)           to anon, authenticated;
grant execute on function public.service_when(text,text)           to anon, authenticated;
grant execute on function public.service_push(text,text,jsonb)     to anon, authenticated;
-- auth_ok et is_valid_service_data : usage interne uniquement (non exposés).

-- =====================================================================
-- RISQUE RÉSIDUEL (honnêteté)
--  - Choisissez des mots de passe robustes ; bcrypt ralentit le forçage mais
--    n'efface pas la faiblesse d'un mot de passe trivial.
--  - L'app conserve les identifiants en local pour rester connectée hors-ligne.
--  - Niveau supérieur (jetons, MFA, reset e-mail) : Supabase Auth.
-- =====================================================================
