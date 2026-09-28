# Good Expectations CRM

A password-protected CRM that runs on Cloudflare Workers + D1.

- **Today**: pipeline value, weighted forecast, won this month, win rate, and a "needs attention" list (overdue tasks, deals past their close date, deals stalled 14+ days in one stage).
- **Contacts**: search, tag filter, sorting, formatted phone numbers, duplicate detection with one-click merge, CSV import (Google Contacts, Outlook, spreadsheets) and CSV export.
- **Pipeline**: drag-and-drop board with win probability per deal, expected close dates, and time-in-stage.
- **Tasks**: overdue / today / upcoming, priorities, and repeating tasks (daily, weekly, every 2 weeks, monthly).
- **Contact timeline**: log calls, emails, meetings and notes. Stage changes are logged automatically.
- Ctrl+K / ⌘K search, keyboard shortcuts (`1`–`4` switch views, `n` new, `/` search), dark mode, phone layout.

## Security

- Every `/api/crm/*` request needs a signed session cookie (HttpOnly, Secure, SameSite=Strict, 30 days).
- Login is rate-limited to 8 wrong attempts per IP per 15 minutes.
- Writes must be JSON from the same origin, which blocks cross-site form attacks.
- All input is validated and length-capped on the server. All output is escaped in the browser.

## Deploy (about 10 minutes)

You need Node 18+ and your Cloudflare account.

```bash
cd crm
npm install
npx wrangler login

# 1. Create the database, then paste the printed database_id into wrangler.toml
npx wrangler d1 create good-expectations-crm

# 2. Create the tables
npm run db:init

# 3. Set your secrets (you'll be prompted for each value)
npx wrangler secret put CRM_PASSWORD      # the password you'll sign in with
npx wrangler secret put SESSION_SECRET    # any long random string, e.g. from: openssl rand -hex 32

# 4. Deploy
npm run deploy
```

`wrangler.toml` routes `goodexpectation.com/crm*` and `goodexpectation.com/api/crm*` to this Worker, so it replaces the current open CRM at the same address. To try it on a `*.workers.dev` URL first, comment out the `routes` block.

The old CRM has no export, so re-add its contacts by hand or put them in a CSV and use **Import CSV**.

## Local development

```bash
printf 'CRM_PASSWORD=test\nSESSION_SECRET=dev-secret-change-me\n' > .dev.vars
npx wrangler d1 execute good-expectations-crm --local --file=schema.sql
npm run dev        # http://localhost:8787/crm
```

## Files

| File | What it is |
|---|---|
| `src/app.html` | The whole front end (HTML, CSS, JS). Opened with no backend, it shows a demo with sample data. |
| `src/worker.js` | The API, login, and page serving. |
| `schema.sql` | Database tables. |
| `build.mjs` | Wraps `src/app.html` into `public/index.html` for the Worker. |

## Changing the password

Run `npx wrangler secret put CRM_PASSWORD`. To sign everyone out, also change `SESSION_SECRET`.
