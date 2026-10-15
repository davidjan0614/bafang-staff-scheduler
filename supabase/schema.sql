create extension if not exists pgcrypto;

create table if not exists public.app_state (
  id smallint primary key default 1 check (id = 1),
  data jsonb not null,
  updated_at timestamptz not null default now()
);

alter table public.app_state enable row level security;
revoke all on public.app_state from anon, authenticated;

create or replace function public.load_schedule(p_password text)
returns jsonb
language plpgsql
security definer
set search_path = public, extensions
as $$
begin
  if encode(digest(p_password, 'sha256'), 'hex') not in (
    '2926a2731f4b312c08982cacf8061eb14bf65c1a87cc5d70e864e079c6220731',
    '2ed927e972728bc356c12808c31656d17ce6a4afded459165923d4b5c25ffd4f'
  ) then
    raise exception 'invalid password';
  end if;
  return (select data from public.app_state where id = 1);
end;
$$;

create or replace function public.save_schedule(p_password text, p_data jsonb)
returns jsonb
language plpgsql
security definer
set search_path = public, extensions
as $$
begin
  if encode(digest(p_password, 'sha256'), 'hex') <> '2926a2731f4b312c08982cacf8061eb14bf65c1a87cc5d70e864e079c6220731' then
    raise exception 'invalid admin password';
  end if;
  update public.app_state set data = p_data, updated_at = now() where id = 1;
  return p_data;
end;
$$;

revoke all on function public.load_schedule(text) from public;
revoke all on function public.save_schedule(text, jsonb) from public;
grant execute on function public.load_schedule(text) to anon, authenticated;
grant execute on function public.save_schedule(text, jsonb) to anon, authenticated;

