-- ═══════════════════════════════════════════════════════════════
--  GPM Fee Management System — Supabase Schema
--  Government Polytechnic, Munger
--  Run this in Supabase SQL Editor
-- ═══════════════════════════════════════════════════════════════

-- Students table
create table if not exists students (
  id            uuid primary key default gen_random_uuid(),
  roll_no       text unique not null,
  name          text not null,
  gender        text,
  category      text,
  pwd           text default 'No',
  course        text,
  year          text,
  mobile        text,
  email         text,
  father_name   text,
  mother_name   text,
  address       text,
  password_hash text not null,
  password_salt text not null,
  is_active     boolean default true,
  created_at    timestamptz default now()
);

-- Fee types table
create table if not exists fee_types (
  id          uuid primary key default gen_random_uuid(),
  name        text not null,
  course      text default 'ALL',
  year        text default 'ALL',
  category    text default 'ALL',
  amount      numeric(10,2) not null,
  is_active   boolean default true,
  created_at  timestamptz default now()
);

-- Fee demands table
create table if not exists fee_demands (
  id            uuid primary key default gen_random_uuid(),
  roll_no       text references students(roll_no),
  fee_type_id   uuid references fee_types(id),
  fee_type_name text,
  amount        numeric(10,2) not null,
  ref_code      text unique not null,
  upi_link      text,
  remarks       text,
  status        text default 'pending',
  created_at    timestamptz default now(),
  updated_at    timestamptz default now()
);

-- Payments table
create table if not exists payments (
  id           uuid primary key default gen_random_uuid(),
  demand_id    uuid references fee_demands(id),
  roll_no      text,
  utr          text unique not null,
  amount_paid  numeric(10,2),
  payment_date date,
  bank_remarks text,
  verified_by  text default 'cashier',
  verified_at  timestamptz default now()
);

-- Receipts table
create table if not exists receipts (
  id            uuid primary key default gen_random_uuid(),
  payment_id    uuid references payments(id),
  receipt_no    text unique not null,
  roll_no       text,
  student_name  text,
  fee_type_name text,
  amount        numeric(10,2),
  issued_at     timestamptz default now()
);

-- Audit log table
create table if not exists audit_logs (
  id         uuid primary key default gen_random_uuid(),
  action     text not null,
  role       text not null,
  identifier text,
  details    jsonb,
  ip_address text,
  created_at timestamptz default now()
);

-- ═══ ROW LEVEL SECURITY ═══════════════════════════════════════
-- All access goes through Cloudflare Worker using service_role
-- Anon key has NO direct access — everything locked down

alter table students     enable row level security;
alter table fee_types    enable row level security;
alter table fee_demands  enable row level security;
alter table payments     enable row level security;
alter table receipts     enable row level security;
alter table audit_logs   enable row level security;

-- Drop existing policies if any
drop policy if exists "deny all students"    on students;
drop policy if exists "deny all fee_types"   on fee_types;
drop policy if exists "deny all fee_demands" on fee_demands;
drop policy if exists "deny all payments"    on payments;
drop policy if exists "deny all receipts"    on receipts;
drop policy if exists "deny all audit_logs"  on audit_logs;

-- DENY ALL — Worker uses service_role key which bypasses RLS
-- This ensures no direct database access even with anon key
create policy "deny all students"    on students    for all using (false);
create policy "deny all fee_types"   on fee_types   for all using (false);
create policy "deny all fee_demands" on fee_demands for all using (false);
create policy "deny all payments"    on payments    for all using (false);
create policy "deny all receipts"    on receipts    for all using (false);
create policy "deny all audit_logs"  on audit_logs  for all using (false);

-- ═══ INDEXES for performance ══════════════════════════════════
create index if not exists idx_students_roll_no    on students(roll_no);
create index if not exists idx_demands_roll_no     on fee_demands(roll_no);
create index if not exists idx_demands_ref_code    on fee_demands(ref_code);
create index if not exists idx_demands_status      on fee_demands(status);
create index if not exists idx_payments_utr        on payments(utr);
create index if not exists idx_receipts_receipt_no on receipts(receipt_no);
create index if not exists idx_receipts_roll_no    on receipts(roll_no);
create index if not exists idx_audit_created_at    on audit_logs(created_at);
