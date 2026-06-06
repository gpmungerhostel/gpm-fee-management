// ═══════════════════════════════════════════════════════════════
//  GPM Fee Management System — Cloudflare Worker (Secure v2)
//  Government Polytechnic, Munger
//
//  CLOUDFLARE SECRETS REQUIRED:
//    SUPABASE_URL        = https://xxxx.supabase.co
//    SUPABASE_SERVICE_KEY = your service_role key (NOT anon key)
//    CASHIER_USER        = cashier
//    CASHIER_PASS        = your-strong-password
//    FRONTEND_URL        = https://your-site.netlify.app
//
//  CLOUDFLARE KV BINDINGS REQUIRED:
//    SESSIONS   (KV namespace for session tokens)
//    RATE_LIMIT (KV namespace for rate limiting)
// ═══════════════════════════════════════════════════════════════

// ── Constants ─────────────────────────────────────────────────
const SESSION_TTL_CASHIER = 60 * 60 * 8;   // 8 hours
const SESSION_TTL_STUDENT = 60 * 60 * 24;  // 24 hours
const MAX_LOGIN_ATTEMPTS  = 5;
const RATE_WINDOW_SECONDS = 60 * 15;       // 15 minutes lockout

// ── CORS ──────────────────────────────────────────────────────
function corsHeaders(env, origin) {
  const allowed = env.FRONTEND_URL || '*';
  const isAllowed = allowed === '*' || origin === allowed;
  return {
    'Access-Control-Allow-Origin': isAllowed ? origin || '*' : 'null',
    'Access-Control-Allow-Methods': 'GET, POST, PATCH, DELETE, OPTIONS',
    'Access-Control-Allow-Headers': 'Content-Type, X-Session-Token',
    'Access-Control-Max-Age': '86400',
  };
}

function jsonRes(data, status = 200, env = {}, origin = '') {
  return new Response(JSON.stringify(data), {
    status,
    headers: { 'Content-Type': 'application/json', ...corsHeaders(env, origin) },
  });
}

function errRes(msg, status = 400, env = {}, origin = '') {
  return jsonRes({ error: msg }, status, env, origin);
}

// ── SHA-256 hashing ───────────────────────────────────────────
async function sha256(text) {
  const buf = await crypto.subtle.digest('SHA-256',
    new TextEncoder().encode(text));
  return Array.from(new Uint8Array(buf))
    .map(b => b.toString(16).padStart(2, '0')).join('');
}

// ── Random string generator ───────────────────────────────────
function randomStr(len = 32) {
  const chars = 'ABCDEFGHIJKLMNOPQRSTUVWXYZabcdefghijklmnopqrstuvwxyz0123456789';
  const arr = new Uint8Array(len);
  crypto.getRandomValues(arr);
  return Array.from(arr).map(b => chars[b % chars.length]).join('');
}

// ── Supabase REST helper (uses service_role — bypasses RLS) ───
async function db(env, method, table, body = null, params = '') {
  const url = `${env.SUPABASE_URL}/rest/v1/${table}${params ? '?' + params : ''}`;
  const headers = {
    'apikey': env.SUPABASE_SERVICE_KEY,
    'Authorization': `Bearer ${env.SUPABASE_SERVICE_KEY}`,
    'Content-Type': 'application/json',
    'Prefer': method === 'POST' ? 'return=representation' : 'return=representation',
  };
  if (method === 'HEAD' || method === 'GET') headers['Prefer'] = 'count=exact';
  const res = await fetch(url, {
    method,
    headers,
    body: body ? JSON.stringify(body) : null,
  });
  const text = await res.text();
  let data = null;
  try { data = JSON.parse(text); } catch { data = text; }
  return { data, status: res.status, headers: res.headers };
}

// ── Rate limiting ─────────────────────────────────────────────
async function checkRateLimit(env, key) {
  if (!env.RATE_LIMIT) return { allowed: true, attempts: 0 };
  const stored = await env.RATE_LIMIT.get(key);
  const attempts = stored ? parseInt(stored) : 0;
  if (attempts >= MAX_LOGIN_ATTEMPTS) return { allowed: false, attempts };
  return { allowed: true, attempts };
}

async function incrementRateLimit(env, key) {
  if (!env.RATE_LIMIT) return;
  const stored = await env.RATE_LIMIT.get(key);
  const attempts = stored ? parseInt(stored) + 1 : 1;
  await env.RATE_LIMIT.put(key, String(attempts), { expirationTtl: RATE_WINDOW_SECONDS });
}

async function clearRateLimit(env, key) {
  if (!env.RATE_LIMIT) return;
  await env.RATE_LIMIT.delete(key);
}

// ── Session management ────────────────────────────────────────
async function createSession(env, role, identifier) {
  if (!env.SESSIONS) return randomStr(32); // fallback if KV not configured
  const token = randomStr(48);
  const ttl = role === 'cashier' ? SESSION_TTL_CASHIER : SESSION_TTL_STUDENT;
  await env.SESSIONS.put(token, JSON.stringify({ role, identifier, created: Date.now() }),
    { expirationTtl: ttl });
  return token;
}

async function validateSession(env, token, requiredRole = null) {
  if (!token) return null;
  if (!env.SESSIONS) return null;
  const stored = await env.SESSIONS.get(token);
  if (!stored) return null;
  const session = JSON.parse(stored);
  if (requiredRole && session.role !== requiredRole) return null;
  return session;
}

async function destroySession(env, token) {
  if (!env.SESSIONS) return;
  await env.SESSIONS.delete(token);
}

// ── Audit logger ──────────────────────────────────────────────
async function audit(env, action, role, identifier, details = {}, ip = '') {
  try {
    await db(env, 'POST', 'audit_logs', { action, role, identifier, details, ip_address: ip });
  } catch (e) { /* non-blocking */ }
}

// ── Input sanitizer ───────────────────────────────────────────
function sanitize(str, maxLen = 200) {
  if (typeof str !== 'string') return '';
  return str.trim().slice(0, maxLen).replace(/[<>]/g, '');
}

function validateRollNo(roll) {
  return /^\d{1,3}\/[A-Z]{2,5}\/\d{4}$/.test(roll);
}

// ══════════════════════════════════════════════════════════════
//  MAIN HANDLER
// ══════════════════════════════════════════════════════════════
export default {
  async fetch(request, env) {
    const origin = request.headers.get('Origin') || '';
    const ip = request.headers.get('CF-Connecting-IP') || 'unknown';

    if (request.method === 'OPTIONS') {
      return new Response(null, { status: 204, headers: corsHeaders(env, origin) });
    }

    const url  = new URL(request.url);
    const path = url.pathname;
    const meth = request.method;
    const token = request.headers.get('X-Session-Token') || '';

    let body = {};
    if (['POST', 'PATCH', 'PUT'].includes(meth)) {
      try { body = await request.json(); } catch { body = {}; }
    }

    // ── Helpers ──────────────────────────────────────────────
    const ok  = (d, s = 200) => jsonRes(d, s, env, origin);
    const err = (m, s = 400) => errRes(m, s, env, origin);

    // ════════════════════════════════════════════════════════
    //  PUBLIC ROUTES (no auth needed)
    // ════════════════════════════════════════════════════════

    // Health check
    if (path === '/api/health' && meth === 'GET') {
      return ok({ status: 'ok', system: 'GPM Fee Management' });
    }

    // Public receipt verification
    if (path === '/api/verify' && meth === 'GET') {
      const rcptNo = sanitize(url.searchParams.get('receipt_no') || '');
      if (!rcptNo) return err('receipt_no required');
      const { data } = await db(env, 'GET', 'receipts',
        null, `receipt_no=eq.${encodeURIComponent(rcptNo)}&select=*,payments(utr,payment_date,amount_paid)`);
      if (!data || data.length === 0) return ok({ found: false });
      await audit(env, 'VERIFY_RECEIPT', 'public', rcptNo, {}, ip);
      return ok({ found: true, receipt: data[0] });
    }

    // Public fee types list (for student QR)
    if (path === '/api/fee-types' && meth === 'GET') {
      const { data } = await db(env, 'GET', 'fee_types', null, 'is_active=eq.true&order=name');
      return ok(data || []);
    }

    // ════════════════════════════════════════════════════════
    //  AUTH ROUTES
    // ════════════════════════════════════════════════════════

    // Cashier login
    if (path === '/api/auth/cashier' && meth === 'POST') {
      const { username, password } = body;
      const rlKey = `cashier_login_${ip}`;
      const { allowed, attempts } = await checkRateLimit(env, rlKey);
      if (!allowed) return err(`Too many attempts. Try after 15 minutes.`, 429);
      if (!username || !password) return err('Username and password required');
      const validUser = username === (env.CASHIER_USER || 'cashier');
      const validPass = password === env.CASHIER_PASS;
      if (!validUser || !validPass) {
        await incrementRateLimit(env, rlKey);
        await audit(env, 'CASHIER_LOGIN_FAILED', 'cashier', username, { attempts: attempts + 1 }, ip);
        return ok({ success: false, message: `Invalid credentials. ${MAX_LOGIN_ATTEMPTS - attempts - 1} attempts remaining.` });
      }
      await clearRateLimit(env, rlKey);
      const sessionToken = await createSession(env, 'cashier', 'cashier');
      await audit(env, 'CASHIER_LOGIN', 'cashier', 'cashier', {}, ip);
      return ok({ success: true, token: sessionToken, role: 'cashier' });
    }

    // Cashier logout
    if (path === '/api/auth/logout' && meth === 'POST') {
      if (token) await destroySession(env, token);
      return ok({ success: true });
    }

    // Student register
    if (path === '/api/auth/register' && meth === 'POST') {
      const { roll_no, name, gender, category, pwd, course, year,
              mobile, email, father_name, mother_name, address, password } = body;
      if (!roll_no || !name || !gender || !category || !course || !year || !mobile || !password) {
        return err('All required fields must be filled');
      }
      if (!validateRollNo(roll_no)) return err('Invalid Roll No. format. Use: 25/CSE/2026');
      if (mobile.length !== 10 || !/^\d+$/.test(mobile)) return err('Invalid mobile number');
      if (password.length < 6) return err('Password must be at least 6 characters');
      // Check duplicate
      const { data: existing } = await db(env, 'GET', 'students', null,
        `roll_no=eq.${encodeURIComponent(roll_no)}&select=roll_no`);
      if (existing && existing.length > 0) return ok({ success: false, message: 'Roll No. already registered' });
      // Hash password with salt
      const salt = randomStr(16);
      const hash = await sha256(password + salt);
      const { data, status } = await db(env, 'POST', 'students', {
        roll_no: sanitize(roll_no), name: sanitize(name), gender, category, pwd,
        course, year, mobile: sanitize(mobile),
        email: sanitize(email || ''), father_name: sanitize(father_name || ''),
        mother_name: sanitize(mother_name || ''), address: sanitize(address || '', 500),
        password_hash: hash, password_salt: salt
      });
      if (status !== 201) return ok({ success: false, message: 'Registration failed' });
      await audit(env, 'STUDENT_REGISTER', 'student', roll_no, { name }, ip);
      return ok({ success: true });
    }

    // Student login
    if (path === '/api/auth/student' && meth === 'POST') {
      const { roll_no, password } = body;
      if (!roll_no || !password) return err('Roll No. and password required');
      const rlKey = `student_login_${ip}`;
      const { allowed, attempts } = await checkRateLimit(env, rlKey);
      if (!allowed) return err('Too many attempts. Try after 15 minutes.', 429);
      const { data } = await db(env, 'GET', 'students', null,
        `roll_no=eq.${encodeURIComponent(roll_no)}&select=*`);
      if (!data || data.length === 0) {
        await incrementRateLimit(env, rlKey);
        return ok({ success: false, message: 'Roll No. not found' });
      }
      const student = data[0];
      const hash = await sha256(password + student.password_salt);
      if (hash !== student.password_hash) {
        await incrementRateLimit(env, rlKey);
        await audit(env, 'STUDENT_LOGIN_FAILED', 'student', roll_no, { attempts: attempts + 1 }, ip);
        return ok({ success: false, message: `Incorrect password. ${MAX_LOGIN_ATTEMPTS - attempts - 1} attempts remaining.` });
      }
      await clearRateLimit(env, rlKey);
      const sessionToken = await createSession(env, 'student', roll_no);
      const { password_hash, password_salt, ...safeStudent } = student;
      await audit(env, 'STUDENT_LOGIN', 'student', roll_no, {}, ip);
      return ok({ success: true, token: sessionToken, student: safeStudent });
    }

    // ════════════════════════════════════════════════════════
    //  PROTECTED ROUTES — validate session first
    // ════════════════════════════════════════════════════════

    // ── STUDENT ROUTES ────────────────────────────────────────
    if (path.startsWith('/api/student/')) {
      const session = await validateSession(env, token, 'student');
      if (!session) return err('Unauthorized — please login', 401);
      const roll = session.identifier;

      // Student demands (only their own)
      if (path === '/api/student/demands' && meth === 'GET') {
        const { data } = await db(env, 'GET', 'fee_demands', null,
          `roll_no=eq.${encodeURIComponent(roll)}&order=created_at.desc&select=*`);
        return ok(data || []);
      }

      // Student receipts (only their own)
      if (path === '/api/student/receipts' && meth === 'GET') {
        const { data } = await db(env, 'GET', 'receipts', null,
          `roll_no=eq.${encodeURIComponent(roll)}&order=issued_at.desc`);
        return ok(data || []);
      }

      return err('Not found', 404);
    }

    // ── CASHIER ROUTES ────────────────────────────────────────
    if (path.startsWith('/api/cashier/')) {
      const session = await validateSession(env, token, 'cashier');
      if (!session) return err('Unauthorized — please login as cashier', 401);

      // Dashboard stats
      if (path === '/api/cashier/dashboard' && meth === 'GET') {
        const today = new Date().toISOString().split('T')[0];
        const [stuRes, pendRes, payRes, recentRes] = await Promise.all([
          db(env, 'HEAD', 'students', null, 'is_active=eq.true&select=id'),
          db(env, 'HEAD', 'fee_demands', null, 'status=eq.pending&select=id'),
          db(env, 'GET', 'payments', null, `payment_date=eq.${today}&select=amount_paid`),
          db(env, 'GET', 'receipts', null, 'order=issued_at.desc&limit=10&select=*'),
        ]);
        const stuCount  = parseInt(stuRes.headers.get('content-range')?.split('/')[1] || '0');
        const pendCount = parseInt(pendRes.headers.get('content-range')?.split('/')[1] || '0');
        const todayPay  = payRes.data || [];
        const todayTotal = todayPay.reduce((s, p) => s + parseFloat(p.amount_paid || 0), 0);
        return ok({ students: stuCount, pending: pendCount,
          today_count: todayPay.length, today_total: todayTotal,
          recent: recentRes.data || [] });
      }

      // All students
      if (path === '/api/cashier/students' && meth === 'GET') {
        const { data } = await db(env, 'GET', 'students', null,
          'is_active=eq.true&order=roll_no&select=id,roll_no,name,gender,category,course,year,mobile,email,created_at');
        return ok(data || []);
      }

      // Single student
      if (path.startsWith('/api/cashier/students/') && meth === 'GET') {
        const roll = decodeURIComponent(path.split('/').pop());
        const [stuRes, demRes] = await Promise.all([
          db(env, 'GET', 'students', null,
            `roll_no=eq.${encodeURIComponent(roll)}&select=id,roll_no,name,gender,category,course,year,mobile,email,father_name,mother_name,address`),
          db(env, 'GET', 'fee_demands', null,
            `roll_no=eq.${encodeURIComponent(roll)}&order=created_at.desc`),
        ]);
        return ok({ student: stuRes.data?.[0] || null, demands: demRes.data || [] });
      }

      // Student lookup for demand form
      if (path === '/api/cashier/student-lookup' && meth === 'GET') {
        const roll = sanitize(url.searchParams.get('roll_no') || '');
        if (!validateRollNo(roll)) return ok(null);
        const { data } = await db(env, 'GET', 'students', null,
          `roll_no=eq.${encodeURIComponent(roll)}&select=name,course,category,year`);
        return ok(data?.[0] || null);
      }

      // Reset student password
      if (path === '/api/cashier/reset-password' && meth === 'POST') {
        const { roll_no, new_password } = body;
        if (!roll_no || !new_password) return err('roll_no and new_password required');
        if (new_password.length < 6) return err('Password must be at least 6 characters');
        const salt = randomStr(16);
        const hash = await sha256(new_password + salt);
        await db(env, 'PATCH', `students?roll_no=eq.${encodeURIComponent(roll_no)}`,
          { password_hash: hash, password_salt: salt });
        await audit(env, 'PASSWORD_RESET', 'cashier', roll_no, {}, ip);
        return ok({ success: true });
      }

      // Fee types list
      if (path === '/api/cashier/fee-types' && meth === 'GET') {
        const { data } = await db(env, 'GET', 'fee_types', null, 'is_active=eq.true&order=name');
        return ok(data || []);
      }

      // Add fee type
      if (path === '/api/cashier/fee-types' && meth === 'POST') {
        const { name, course, year, category, amount } = body;
        if (!name || !amount || isNaN(amount)) return err('Name and amount required');
        const { data, status } = await db(env, 'POST', 'fee_types',
          { name: sanitize(name), course: course || 'ALL',
            year: year || 'ALL', category: category || 'ALL',
            amount: parseFloat(amount) });
        await audit(env, 'FEE_TYPE_ADDED', 'cashier', name, { amount }, ip);
        return ok(data, status);
      }

      // Edit fee type
      if (path.startsWith('/api/cashier/fee-types/') && meth === 'PATCH') {
        const id = path.split('/').pop();
        const { name, course, year, category, amount } = body;
        const { data } = await db(env, 'PATCH', `fee_types?id=eq.${id}`,
          { name: sanitize(name), course, year, category, amount: parseFloat(amount) });
        await audit(env, 'FEE_TYPE_EDITED', 'cashier', id, { name, amount }, ip);
        return ok(data);
      }

      // Delete fee type (soft delete)
      if (path.startsWith('/api/cashier/fee-types/') && meth === 'DELETE') {
        const id = path.split('/').pop();
        await db(env, 'PATCH', `fee_types?id=eq.${id}`, { is_active: false });
        await audit(env, 'FEE_TYPE_DELETED', 'cashier', id, {}, ip);
        return ok({ success: true });
      }

      // Issue demand
      if (path === '/api/cashier/demands' && meth === 'POST') {
        const { roll_no, fee_type_id, fee_type_name, amount, ref_code, upi_link, remarks } = body;
        if (!roll_no || !fee_type_id || !amount || !ref_code) return err('Missing required fields');
        if (!validateRollNo(roll_no)) return err('Invalid Roll No.');
        if (isNaN(amount) || amount <= 0) return err('Invalid amount');
        // Check duplicate ref_code
        const { data: existing } = await db(env, 'GET', 'fee_demands', null,
          `ref_code=eq.${encodeURIComponent(ref_code)}&select=id`);
        if (existing && existing.length > 0) {
          return ok({ success: false, message: 'Demand already exists for this student, fee type and year' });
        }
        const { data, status } = await db(env, 'POST', 'fee_demands', {
          roll_no, fee_type_id, fee_type_name: sanitize(fee_type_name),
          amount: parseFloat(amount), ref_code, upi_link,
          remarks: sanitize(remarks || ''), status: 'pending'
        });
        if (status !== 201) return ok({ success: false, message: 'Failed to create demand' });
        await audit(env, 'DEMAND_ISSUED', 'cashier', roll_no,
          { fee_type: fee_type_name, amount, ref_code }, ip);
        return ok({ success: true, demand: data?.[0] });
      }

      // All demands (manage tab)
      if (path === '/api/cashier/demands' && meth === 'GET') {
        const { data } = await db(env, 'GET', 'fee_demands', null,
          'order=created_at.desc&select=*,students(name)');
        return ok(data || []);
      }

      // Edit demand
      if (path.startsWith('/api/cashier/demands/') && meth === 'PATCH') {
        const id = path.split('/').pop();
        const allowed = ['amount', 'remarks', 'status', 'upi_link'];
        const update = {};
        for (const k of allowed) if (body[k] !== undefined) update[k] = body[k];
        if (update.amount) update.amount = parseFloat(update.amount);
        update.updated_at = new Date().toISOString();
        const { data } = await db(env, 'PATCH', `fee_demands?id=eq.${id}`, update);
        await audit(env, 'DEMAND_EDITED', 'cashier', id, update, ip);
        return ok(data);
      }

      // Delete demand
      if (path.startsWith('/api/cashier/demands/') && meth === 'DELETE') {
        const id = path.split('/').pop();
        const { data: d } = await db(env, 'GET', 'fee_demands', null,
          `id=eq.${id}&select=status,ref_code`);
        if (!d?.[0]) return err('Demand not found', 404);
        if (d[0].status === 'paid') return err('Cannot delete a paid demand');
        await db(env, 'DELETE', `fee_demands?id=eq.${id}`);
        await audit(env, 'DEMAND_DELETED', 'cashier', id, { ref_code: d[0].ref_code }, ip);
        return ok({ success: true });
      }

      // Demand lookup by ref code
      if (path === '/api/cashier/demand-lookup' && meth === 'GET') {
        const ref = sanitize(url.searchParams.get('ref_code') || '');
        if (!ref) return ok(null);
        const { data } = await db(env, 'GET', 'fee_demands', null,
          `ref_code=eq.${encodeURIComponent(ref)}&select=*,students(name,course)`);
        return ok(data?.[0] || null);
      }

      // Verify payment
      if (path === '/api/cashier/verify-payment' && meth === 'POST') {
        const { ref_code, utr, amount_paid, payment_date, bank_remarks } = body;
        if (!ref_code || !utr || !amount_paid || !payment_date) {
          return err('ref_code, utr, amount_paid and payment_date are required');
        }
        if (!/^\d{10,22}$/.test(utr)) return err('Invalid UTR format');
        if (isNaN(amount_paid) || amount_paid <= 0) return err('Invalid amount');
        const { data: demArr } = await db(env, 'GET', 'fee_demands', null,
          `ref_code=eq.${encodeURIComponent(sanitize(ref_code))}&select=*,students(*)`);
        const demand = demArr?.[0];
        if (!demand) return ok({ success: false, message: 'Reference code not found' });
        if (demand.status === 'paid') return ok({ success: false, message: 'Already paid' });
        const { data: existUTR } = await db(env, 'GET', 'payments', null,
          `utr=eq.${utr}&select=id`);
        if (existUTR?.length > 0) return ok({ success: false, message: 'UTR already recorded in system' });
        // Insert payment
        const { data: payArr, status: ps } = await db(env, 'POST', 'payments', {
          demand_id: demand.id, roll_no: demand.roll_no,
          utr: sanitize(utr), amount_paid: parseFloat(amount_paid),
          payment_date, bank_remarks: sanitize(bank_remarks || ''),
        });
        if (ps !== 201) return ok({ success: false, message: 'Payment insert failed' });
        const payment = payArr?.[0];
        // Mark demand paid
        await db(env, 'PATCH', `fee_demands?id=eq.${demand.id}`,
          { status: 'paid', updated_at: new Date().toISOString() });
        // Generate receipt number
        const rcptYear  = new Date().getFullYear();
        const yearPrefix = `GPM/FEE/${rcptYear}/`;
        const { headers: rh } = await db(env, 'HEAD', 'receipts', null,
          `receipt_no=like.${yearPrefix}*&select=id`);
        const rcptCount = parseInt(rh.get('content-range')?.split('/')[1] || '0');
        const rcptNo = `${yearPrefix}${String(rcptCount + 1).padStart(4, '0')}`;
        const { data: rcptArr, status: rs } = await db(env, 'POST', 'receipts', {
          payment_id: payment.id, receipt_no: rcptNo,
          roll_no: demand.roll_no, student_name: demand.students?.name,
          fee_type_name: demand.fee_type_name, amount: parseFloat(amount_paid),
        });
        if (rs !== 201) return ok({ success: false, message: 'Receipt generation failed' });
        await audit(env, 'PAYMENT_VERIFIED', 'cashier', demand.roll_no,
          { ref_code, utr, amount: amount_paid, receipt_no: rcptNo }, ip);
        return ok({
          success: true, receipt_no: rcptNo,
          receipt: rcptArr?.[0], demand, payment,
          student: demand.students,
        });
      }

      // Bulk verify
      if (path === '/api/cashier/bulk-verify' && meth === 'POST') {
        const { items } = body;
        if (!Array.isArray(items) || items.length === 0) return err('items array required');
        if (items.length > 50) return err('Maximum 50 items per bulk verify');
        const results = [];
        const today = new Date().toISOString().split('T')[0];
        for (const item of items) {
          const { ref_code, utr } = item;
          const { data: dArr } = await db(env, 'GET', 'fee_demands', null,
            `ref_code=eq.${encodeURIComponent(sanitize(ref_code))}&select=*,students(name)`);
          const demand = dArr?.[0];
          if (!demand)          { results.push({ ref_code, utr, status: '❌ Ref not found' }); continue; }
          if (demand.status === 'paid') { results.push({ ref_code, utr, status: '⚠️ Already paid' }); continue; }
          const { data: eu } = await db(env, 'GET', 'payments', null, `utr=eq.${utr}&select=id`);
          if (eu?.length > 0)   { results.push({ ref_code, utr, status: '⚠️ UTR duplicate' }); continue; }
          const { data: pArr }  = await db(env, 'POST', 'payments', {
            demand_id: demand.id, roll_no: demand.roll_no,
            utr: sanitize(utr), amount_paid: demand.amount, payment_date: today,
          });
          await db(env, 'PATCH', `fee_demands?id=eq.${demand.id}`,
            { status: 'paid', updated_at: new Date().toISOString() });
          const rcptYear = new Date().getFullYear();
          const yp = `GPM/FEE/${rcptYear}/`;
          const { headers: rh } = await db(env, 'HEAD', 'receipts', null,
            `receipt_no=like.${yp}*&select=id`);
          const rc = parseInt(rh.get('content-range')?.split('/')[1] || '0');
          const rcptNo = `${yp}${String(rc + 1).padStart(4, '0')}`;
          await db(env, 'POST', 'receipts', {
            payment_id: pArr?.[0]?.id, receipt_no: rcptNo,
            roll_no: demand.roll_no, student_name: demand.students?.name,
            fee_type_name: demand.fee_type_name, amount: demand.amount,
          });
          await audit(env, 'BULK_PAYMENT_VERIFIED', 'cashier', demand.roll_no,
            { ref_code, utr, receipt_no: rcptNo }, ip);
          results.push({ ref_code, utr, status: `✅ Verified — ${rcptNo}` });
        }
        return ok({ results });
      }

      // Receipts list
      if (path === '/api/cashier/receipts' && meth === 'GET') {
        const q    = sanitize(url.searchParams.get('q') || '');
        const date = sanitize(url.searchParams.get('date') || '');
        let params = 'order=issued_at.desc&limit=200&select=*,payments(utr,payment_date)';
        if (date) params += `&issued_at=gte.${date}T00:00:00&issued_at=lte.${date}T23:59:59`;
        const { data } = await db(env, 'GET', 'receipts', null, params);
        let list = data || [];
        if (q) {
          const ql = q.toLowerCase();
          list = list.filter(r =>
            r.roll_no?.toLowerCase().includes(ql) ||
            r.student_name?.toLowerCase().includes(ql) ||
            r.receipt_no?.toLowerCase().includes(ql)
          );
        }
        return ok(list);
      }

      // Single receipt
      if (path.startsWith('/api/cashier/receipts/') && meth === 'GET') {
        const rcptNo = decodeURIComponent(path.split('/').pop());
        const { data } = await db(env, 'GET', 'receipts', null,
          `receipt_no=eq.${encodeURIComponent(rcptNo)}&select=*,payments(utr,payment_date,bank_remarks)`);
        return ok(data?.[0] || null);
      }

      // Reports
      if (path === '/api/cashier/reports' && meth === 'GET') {
        const ftId = sanitize(url.searchParams.get('fee_type_id') || '');
        let params = 'select=*,students(name,course,category)&order=created_at.desc';
        if (ftId) params += `&fee_type_id=eq.${ftId}`;
        const { data } = await db(env, 'GET', 'fee_demands', null, params);
        return ok(data || []);
      }

      // Audit logs
      if (path === '/api/cashier/audit-logs' && meth === 'GET') {
        const { data } = await db(env, 'GET', 'audit_logs', null,
          'order=created_at.desc&limit=100');
        return ok(data || []);
      }

      return err('Not found', 404);
    }

    return err('Not found', 404);
  },
};
