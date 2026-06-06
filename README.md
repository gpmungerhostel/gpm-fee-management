# GPM Fee Management System
### Government Polytechnic, Munger — Bihar

A secure, zero-cost digital fee collection system using UPI payments.

---

## Architecture

```
GitHub (source code)
    ↓ auto-deploy
Cloudflare Pages (hosts HTML frontend)
    ↓ API calls
Cloudflare Worker (secure API — all secrets here)
    ↓ database queries
Supabase PostgreSQL (data storage)
```

## Security Features

- ✅ Zero sensitive data in HTML/frontend
- ✅ SHA-256 + salt password hashing
- ✅ Server-side session tokens (8hr cashier / 24hr student)
- ✅ Rate limiting — 5 attempts per 15 minutes
- ✅ CORS restricted to your domain only
- ✅ All RLS policies deny direct DB access
- ✅ Worker uses service_role key (bypasses RLS safely)
- ✅ Input sanitization and validation
- ✅ Complete audit trail of all actions
- ✅ Student can only access own data (server-enforced)

## Files

| File | Purpose |
|---|---|
| `index.html` | Frontend — student & cashier portal |
| `worker.js` | Cloudflare Worker — secure API layer |
| `schema.sql` | Supabase database schema |

## Setup Instructions

### Step 1 — Supabase Database
1. Create project at [supabase.com](https://supabase.com)
2. Go to SQL Editor → paste contents of `schema.sql` → Run
3. Go to Settings → API Keys → Legacy tab
4. Copy **Project URL** and **anon key**
5. Also copy **service_role key** (needed for Worker)

### Step 2 — Cloudflare KV Namespaces
1. Go to [dash.cloudflare.com](https://dash.cloudflare.com)
2. Workers & Pages → KV → Create namespace
3. Create two namespaces:
   - `GPM_SESSIONS`
   - `GPM_RATE_LIMIT`
4. Note the namespace IDs

### Step 3 — Cloudflare Worker
1. Workers & Pages → Create → Worker → Start with Hello World
2. Name: `gpm-fee` → Deploy
3. Edit code → paste `worker.js` contents → Deploy
4. Settings → Variables and Secrets → add:

| Secret | Value |
|---|---|
| `SUPABASE_URL` | `https://xxxx.supabase.co` |
| `SUPABASE_SERVICE_KEY` | service_role key from Supabase |
| `CASHIER_USER` | `cashier` |
| `CASHIER_PASS` | your strong password |
| `FRONTEND_URL` | your Netlify/Pages URL |

5. Settings → Bindings → KV Namespaces → add:
   - Variable: `SESSIONS` → Namespace: `GPM_SESSIONS`
   - Variable: `RATE_LIMIT` → Namespace: `GPM_RATE_LIMIT`

### Step 4 — Deploy Frontend
1. Rename `index.html` → open in Notepad
2. Set `WORKER_URL` to your worker URL
3. Host on Netlify (drag & drop) or Cloudflare Pages

## Default Login
- **Cashier:** username `cashier` / password = what you set in CASHIER_PASS secret
- **Students:** self-register with Roll No. format `25/CSE/2026`

## Roll No. Format
```
25 / CSE / 2026
↑     ↑     ↑
No  Branch  Year

Branches: CE, CSE, EE, EC, ME, FTS
```

## Receipt Format
- Receipt No.: `GPM/FEE/2026/0001` (resets every year)
- A4 page: 1 student copy + 1 office copy
- QR code on receipt links to public verification page
