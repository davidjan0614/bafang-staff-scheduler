create or replace function public.change_own_pin(
  p_password text,
  p_employee_id text,
  p_new_pin text
)
returns boolean
language plpgsql
security definer
set search_path = public, extensions
as $$
declare
  v_employee_name text;
  v_data jsonb;
  v_audit jsonb;
begin
  if not exists (
    select 1 from public.employee_credentials
    where employee_id = p_employee_id
      and pin_hash = encode(digest(p_password, 'sha256'), 'hex')
  ) then
    raise exception 'invalid current password';
  end if;
  if p_new_pin !~ '^[0-9]{4}$' or p_new_pin = '8888' then
    raise exception 'new pin must be four digits and cannot be admin pin';
  end if;
  if p_new_pin = p_password then
    raise exception 'new pin must differ from current pin';
  end if;
  if exists (
    select 1 from public.employee_credentials
    where pin_hash = encode(digest(p_new_pin, 'sha256'), 'hex')
      and employee_id <> p_employee_id
  ) then
    raise exception 'employee pin already in use';
  end if;
  select employee->>'name' into v_employee_name
  from jsonb_array_elements((select data->'employees' from public.app_state where id = 1)) employee
  where employee->>'id' = p_employee_id
    and coalesce((employee->>'active')::boolean, false)
  limit 1;
  if v_employee_name is null then
    raise exception 'employee not found or inactive';
  end if;
  update public.employee_credentials
  set pin_hash = encode(digest(p_new_pin, 'sha256'), 'hex'), updated_at = now()
  where employee_id = p_employee_id;
  select data into v_data from public.app_state where id = 1 for update;
  v_audit := jsonb_build_object(
    'id', 'a' || floor(extract(epoch from clock_timestamp()) * 1000)::bigint,
    'at', to_jsonb(clock_timestamp()),
    'actor', v_employee_name,
    'action', '變更個人密碼',
    'detail', v_employee_name || ' 已自行更新登入密碼'
  );
  v_data := jsonb_set(v_data, '{auditLog}', jsonb_build_array(v_audit) || coalesce(v_data->'auditLog', '[]'::jsonb), true);
  update public.app_state set data = v_data, updated_at = now() where id = 1;
  return true;
end;
$$;

revoke all on function public.change_own_pin(text, text, text) from public;
grant execute on function public.change_own_pin(text, text, text) to anon, authenticated;
