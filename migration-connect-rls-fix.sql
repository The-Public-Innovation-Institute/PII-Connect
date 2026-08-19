-- PII Connect — RLS hardening
-- Fixes two issues:
--   1. Any signed-in user could set their own profiles.connect_role / role to 'admin'.
--   2. connect_invited_alumni was readable by anon, exposing every invited email.
--
-- Ship this together with the updated index.html, which moves the join flow
-- onto the two RPCs defined below. Applying this alone will break sign-up.

begin;

-- ─────────────────────────────────────────────────────────────
-- 1. Stop clients from writing privileged profile columns
-- ─────────────────────────────────────────────────────────────

create or replace function public.guard_profile_privileged_columns()
returns trigger
language plpgsql
security definer
set search_path = public
as $$
begin
  -- service_role / internal jobs have no auth.uid(); let them through
  if auth.uid() is null then
    return new;
  end if;

  -- trusted RPCs below set this flag for the duration of their transaction
  if current_setting('app.bypass_profile_guard', true) = 'on' then
    return new;
  end if;

  -- platform admins may still promote people
  if exists (
    select 1 from public.profiles p
    where p.id = auth.uid() and (p.role = 'admin' or p.connect_role = 'admin')
  ) then
    return new;
  end if;

  if new.role              is distinct from old.role
  or new.connect_role      is distinct from old.connect_role
  or new.connect_joined_at is distinct from old.connect_joined_at
  or new.email             is distinct from old.email
  or new.id                is distinct from old.id then
    raise exception 'You cannot change your own role or email here.'
      using errcode = '42501';
  end if;

  return new;
end;
$$;

drop trigger if exists trg_guard_profile_privileged_columns on public.profiles;
create trigger trg_guard_profile_privileged_columns
  before update on public.profiles
  for each row execute function public.guard_profile_privileged_columns();

-- ─────────────────────────────────────────────────────────────
-- 2. Close the public read on the invite list
-- ─────────────────────────────────────────────────────────────

drop policy if exists "invited public lookup" on public.connect_invited_alumni;

-- Callers can ask "is THIS email invited?" and get a yes/no.
-- They can no longer enumerate the list.
create or replace function public.has_pending_connect_invite(p_email text)
returns boolean
language sql
security definer
set search_path = public
as $$
  select exists (
    select 1 from public.connect_invited_alumni
    where lower(email) = lower(trim(p_email))
      and status = 'invited'
  );
$$;

grant execute on function public.has_pending_connect_invite(text) to anon, authenticated;

-- ─────────────────────────────────────────────────────────────
-- 3. Claim an invite — derives the email from the session,
--    so a caller can only ever claim their own.
-- ─────────────────────────────────────────────────────────────

create or replace function public.claim_connect_invite()
returns boolean
language plpgsql
security definer
set search_path = public
as $$
declare
  v_uid   uuid := auth.uid();
  v_email text;
  v_inv   public.connect_invited_alumni%rowtype;
begin
  if v_uid is null then
    raise exception 'Not signed in.' using errcode = '42501';
  end if;

  select email into v_email from auth.users where id = v_uid;
  if v_email is null then
    return false;
  end if;

  select * into v_inv
  from public.connect_invited_alumni
  where lower(email) = lower(v_email) and status = 'invited'
  limit 1;

  if not found then
    return false;
  end if;

  perform set_config('app.bypass_profile_guard', 'on', true);

  update public.profiles
     set connect_role      = 'alumni',
         connect_joined_at = coalesce(connect_joined_at, now())
   where id = v_uid;

  insert into public.connect_alumni_profiles (user_id, grad_program)
  values (v_uid, v_inv.program_name)
  on conflict (user_id) do nothing;

  update public.connect_invited_alumni
     set status = 'joined', joined_at = now()
   where id = v_inv.id;

  return true;
end;
$$;

grant execute on function public.claim_connect_invite() to authenticated;

commit;
