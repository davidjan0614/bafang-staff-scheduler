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

create or replace function public.submit_leave_request(
  p_password text,
  p_employee_id text,
  p_date date,
  p_reason text default ''
)
returns jsonb
language plpgsql
security definer
set search_path = public, extensions
as $$
declare
  v_data jsonb;
  v_employee jsonb;
  v_request jsonb;
  v_audit jsonb;
begin
  if encode(digest(p_password, 'sha256'), 'hex') <> '2ed927e972728bc356c12808c31656d17ce6a4afded459165923d4b5c25ffd4f' then
    raise exception 'invalid employee password';
  end if;
  if p_date < current_date then
    raise exception 'leave date cannot be in the past';
  end if;
  select employee into v_employee
  from jsonb_array_elements((select data->'employees' from public.app_state where id = 1)) employee
  where employee->>'id' = p_employee_id and coalesce((employee->>'active')::boolean, false)
  limit 1;
  if v_employee is null then
    raise exception 'employee not found';
  end if;
  select data into v_data from public.app_state where id = 1 for update;
  v_request := jsonb_build_object(
    'id', 'r' || floor(extract(epoch from clock_timestamp()) * 1000)::bigint,
    'employeeId', p_employee_id,
    'date', to_char(p_date, 'YYYY-MM-DD'),
    'reason', left(coalesce(p_reason, ''), 120),
    'status', 'pending',
    'createdAt', to_jsonb(clock_timestamp()),
    'decidedAt', null
  );
  v_audit := jsonb_build_object(
    'id', 'a' || floor(extract(epoch from clock_timestamp()) * 1000)::bigint,
    'at', to_jsonb(clock_timestamp()),
    'actor', v_employee->>'name',
    'action', '提出休假申請',
    'detail', (v_employee->>'name') || ' ' || to_char(p_date, 'YYYY-MM-DD')
  );
  v_data := jsonb_set(v_data, '{leaveRequests}', coalesce(v_data->'leaveRequests', '[]'::jsonb) || jsonb_build_array(v_request), true);
  v_data := jsonb_set(v_data, '{auditLog}', jsonb_build_array(v_audit) || coalesce(v_data->'auditLog', '[]'::jsonb), true);
  update public.app_state set data = v_data, updated_at = now() where id = 1;
  return v_request;
end;
$$;

revoke all on function public.load_schedule(text) from public;
revoke all on function public.save_schedule(text, jsonb) from public;
revoke all on function public.submit_leave_request(text, text, date, text) from public;
grant execute on function public.load_schedule(text) to anon, authenticated;
grant execute on function public.save_schedule(text, jsonb) to anon, authenticated;
grant execute on function public.submit_leave_request(text, text, date, text) to anon, authenticated;
