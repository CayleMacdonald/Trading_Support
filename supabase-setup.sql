-- Run once in Supabase: SQL Editor > New query > paste > Run.
create table if not exists public.profiles (
  id uuid primary key references auth.users(id) on delete cascade,
  username text not null,
  created_at timestamptz not null default now(),
  constraint username_format check (username ~ '^[a-z0-9_]{3,20}$')
);
create unique index if not exists profiles_username_key on public.profiles (lower(username));
alter table public.profiles enable row level security;
drop policy if exists "read own profile" on public.profiles;
create policy "read own profile" on public.profiles for select using (auth.uid() = id);

-- create the profile automatically when someone signs up
create or replace function public.handle_new_user() returns trigger
language plpgsql security definer set search_path = '' as $$
begin
  insert into public.profiles (id, username) values (new.id, coalesce(lower(new.raw_user_meta_data->>'username'), 'user_' || substr(new.id::text, 1, 8)));
  return new;
end $$;
drop trigger if exists on_auth_user_created on auth.users;
create trigger on_auth_user_created after insert on auth.users
  for each row execute function public.handle_new_user();

-- used by the sign-in page: username -> email
create or replace function public.email_for_username(u text) returns text
language sql security definer set search_path = '' stable as $$
  select au.email::text from public.profiles p join auth.users au on au.id = p.id where p.username = lower(u)
$$;
-- used by the sign-up page: is the username free?
create or replace function public.username_taken(u text) returns boolean
language sql security definer set search_path = '' stable as $$
  select exists (select 1 from public.profiles where username = lower(u))
$$;
revoke all on function public.email_for_username(text), public.username_taken(text) from public;
grant execute on function public.email_for_username(text), public.username_taken(text) to anon, authenticated;
