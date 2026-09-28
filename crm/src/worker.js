// Good Expectations CRM — Cloudflare Worker
// Serves the app at /crm and a password-protected JSON API at /api/crm/*.
import APP_HTML from "../public/index.html";

const COOKIE = "ge_crm";
const SESSION_DAYS = 30;
const MAX_ATTEMPTS = 8;              // per IP ...
const ATTEMPT_WINDOW_MS = 15 * 60e3; // ... per 15 minutes
const STAGES = ["lead", "contacted", "proposal", "negotiation", "won", "lost"];
const ACTIVITY_TYPES = ["note", "call", "email", "meeting", "system"];
const PRIORITIES = ["low", "normal", "high"];
const RECURRENCES = ["none", "daily", "weekly", "biweekly", "monthly"];

// ---------- helpers ----------
const now = () => new Date().toISOString();
const uid = () => crypto.randomUUID();
const enc = new TextEncoder();

function json(data, status = 200, headers = {}) {
  return new Response(JSON.stringify(data), {
    status,
    headers: { "content-type": "application/json; charset=utf-8", "cache-control": "no-store", ...headers },
  });
}
const err = (msg, status = 400) => json({ error: msg }, status);

function str(v, max = 500) {
  if (v === undefined || v === null) return "";
  return String(v).trim().slice(0, max);
}
function oneOf(v, list, fallback) { return list.includes(v) ? v : fallback; }
function isDate(v) { return v === "" || /^\d{4}-\d{2}-\d{2}$/.test(v); }
function num(v, fallback = 0) {
  const n = Number(v);
  return Number.isFinite(n) ? n : fallback;
}
function tagsIn(v) {
  const arr = Array.isArray(v) ? v : String(v || "").split(",");
  return JSON.stringify([...new Set(arr.map((t) => str(t, 40).toLowerCase()).filter(Boolean))].slice(0, 20));
}

function b64url(buf) {
  return btoa(String.fromCharCode(...new Uint8Array(buf))).replace(/\+/g, "-").replace(/\//g, "_").replace(/=+$/, "");
}
async function hmac(secret, msg) {
  const key = await crypto.subtle.importKey("raw", enc.encode(secret), { name: "HMAC", hash: "SHA-256" }, false, ["sign"]);
  return b64url(await crypto.subtle.sign("HMAC", key, enc.encode(msg)));
}
// Constant-time compare via HMAC of both sides.
async function safeEqual(a, b, secret) {
  const [x, y] = await Promise.all([hmac(secret, "cmp:" + a), hmac(secret, "cmp:" + b)]);
  let diff = x.length ^ y.length;
  for (let i = 0; i < Math.min(x.length, y.length); i++) diff |= x.charCodeAt(i) ^ y.charCodeAt(i);
  return diff === 0;
}
async function makeToken(secret) {
  const exp = String(Date.now() + SESSION_DAYS * 864e5);
  return exp + "." + (await hmac(secret, "session:" + exp));
}
async function validToken(token, secret) {
  if (!token || !token.includes(".")) return false;
  const [exp, sig] = token.split(".");
  if (!/^\d+$/.test(exp) || Number(exp) < Date.now()) return false;
  return safeEqual(sig, await hmac(secret, "session:" + exp), secret);
}
function readCookie(req, name) {
  const m = (req.headers.get("cookie") || "").match(new RegExp("(?:^|;\\s*)" + name + "=([^;]+)"));
  return m ? decodeURIComponent(m[1]) : "";
}
function sessionCookie(value, maxAge, secure) {
  return `${COOKIE}=${value}; Path=/; HttpOnly;${secure ? " Secure;" : ""} SameSite=Strict; Max-Age=${maxAge}`;
}

// ---------- row mappers ----------
const contactOut = (r) => ({ ...r, tags: JSON.parse(r.tags || "[]") });
const taskOut = (r) => ({ ...r, done: !!r.done });

function contactFields(b) {
  return {
    name: str(b.name, 120),
    company: str(b.company, 120),
    title: str(b.title, 120),
    email: str(b.email, 200).toLowerCase(),
    phone: str(b.phone, 40),
    source: str(b.source, 60),
    tags: tagsIn(b.tags),
    notes: str(b.notes, 5000),
  };
}

function nextDue(date, rec) {
  const d = date ? new Date(date + "T12:00:00Z") : new Date();
  if (rec === "daily") d.setUTCDate(d.getUTCDate() + 1);
  else if (rec === "weekly") d.setUTCDate(d.getUTCDate() + 7);
  else if (rec === "biweekly") d.setUTCDate(d.getUTCDate() + 14);
  else if (rec === "monthly") d.setUTCMonth(d.getUTCMonth() + 1);
  return d.toISOString().slice(0, 10);
}

async function logSystem(db, body, contact_id, deal_id) {
  const a = { id: uid(), type: "system", body, contact_id: contact_id || null, deal_id: deal_id || null, created_at: now() };
  await db.prepare("INSERT INTO activities (id,type,body,contact_id,deal_id,created_at) VALUES (?,?,?,?,?,?)")
    .bind(a.id, a.type, a.body, a.contact_id, a.deal_id, a.created_at).run();
  return a;
}

const INSERT_CONTACT = "INSERT INTO contacts (id,name,company,title,email,phone,source,tags,notes,created_at,updated_at) VALUES (?,?,?,?,?,?,?,?,?,?,?)";
const INSERT_TASK = "INSERT INTO tasks (id,title,due_date,priority,recurrence,contact_id,deal_id,done,done_at,created_at,updated_at) VALUES (?,?,?,?,?,?,?,?,?,?,?)";

// ---------- API ----------
async function handleApi(req, env, path) {
  const db = env.DB;
  const method = req.method;
  const secure = new URL(req.url).protocol === "https:";

  if (!env.CRM_PASSWORD || !env.SESSION_SECRET) {
    return err("Server not configured: set CRM_PASSWORD and SESSION_SECRET secrets.", 500);
  }

  // CSRF defence: mutations must be JSON and same-origin.
  if (method !== "GET") {
    const origin = req.headers.get("origin");
    if (origin && new URL(origin).host !== new URL(req.url).host) return err("Bad origin", 403);
    if (method !== "DELETE" && !(req.headers.get("content-type") || "").includes("application/json")) return err("JSON required", 415);
  }
  const body = method === "GET" || method === "DELETE" ? {} : await req.json().catch(() => ({}));

  // --- auth endpoints ---
  if (path === "/login" && method === "POST") {
    const ip = req.headers.get("cf-connecting-ip") || "local";
    const since = Date.now() - ATTEMPT_WINDOW_MS;
    await db.prepare("DELETE FROM login_attempts WHERE at < ?").bind(since).run();
    const { n } = await db.prepare("SELECT COUNT(*) AS n FROM login_attempts WHERE ip = ? AND at >= ?").bind(ip, since).first();
    if (n >= MAX_ATTEMPTS) return err("Too many attempts. Try again in 15 minutes.", 429);
    const ok = await safeEqual(str(body.password, 200), env.CRM_PASSWORD, env.SESSION_SECRET);
    if (!ok) {
      await db.prepare("INSERT INTO login_attempts (ip, at) VALUES (?, ?)").bind(ip, Date.now()).run();
      return err("Wrong password", 401);
    }
    await db.prepare("DELETE FROM login_attempts WHERE ip = ?").bind(ip).run();
    return json({ ok: true }, 200, { "set-cookie": sessionCookie(await makeToken(env.SESSION_SECRET), SESSION_DAYS * 86400, secure) });
  }
  if (path === "/logout" && method === "POST") {
    return json({ ok: true }, 200, { "set-cookie": sessionCookie("", 0, secure) });
  }

  // --- everything below requires a session ---
  if (!(await validToken(readCookie(req, COOKIE), env.SESSION_SECRET))) return err("Not signed in", 401);

  if (path === "/me") return json({ authed: true });

  if (path === "/bootstrap" && method === "GET") {
    const [c, d, t, a] = await db.batch([
      db.prepare("SELECT * FROM contacts ORDER BY name COLLATE NOCASE"),
      db.prepare("SELECT * FROM deals ORDER BY updated_at DESC"),
      db.prepare("SELECT * FROM tasks ORDER BY done, due_date"),
      db.prepare("SELECT * FROM activities ORDER BY created_at DESC LIMIT 500"),
    ]);
    return json({
      contacts: c.results.map(contactOut),
      deals: d.results,
      tasks: t.results.map(taskOut),
      activities: a.results,
    });
  }

  const [, resource, id] = path.split("/"); // "", resource, id

  // ----- contacts -----
  if (resource === "contacts") {
    if (id === "import" && method === "POST") {
      const rows = Array.isArray(body.rows) ? body.rows.slice(0, 2000) : [];
      const ts = now();
      const stmts = [];
      const created = [];
      for (const r of rows) {
        const f = contactFields(r);
        if (!f.name) continue;
        const c = { id: uid(), ...f, created_at: ts, updated_at: ts };
        created.push(contactOut(c));
        stmts.push(db.prepare(INSERT_CONTACT).bind(c.id, c.name, c.company, c.title, c.email, c.phone, c.source, c.tags, c.notes, ts, ts));
      }
      if (stmts.length) await db.batch(stmts);
      return json({ imported: created.length, contacts: created });
    }
    if (id === "bulk-delete" && method === "POST") {
      const ids = [...new Set((Array.isArray(body.ids) ? body.ids : []).map((x) => str(x, 64)).filter(Boolean))].slice(0, 100);
      if (!ids.length) return err("No contacts selected.");
      const marks = ids.map(() => "?").join(",");
      await db.batch([
        db.prepare(`UPDATE deals SET contact_id=NULL WHERE contact_id IN (${marks})`).bind(...ids),
        db.prepare(`UPDATE tasks SET contact_id=NULL WHERE contact_id IN (${marks})`).bind(...ids),
        db.prepare(`DELETE FROM activities WHERE contact_id IN (${marks})`).bind(...ids),
        db.prepare(`DELETE FROM contacts WHERE id IN (${marks})`).bind(...ids),
      ]);
      return json({ deleted: ids.length });
    }
    if (id === "merge" && method === "POST") {
      const keep = str(body.keep_id, 64), drop = str(body.merge_id, 64);
      if (!keep || !drop || keep === drop) return err("Pick two different contacts");
      const [a, b] = await Promise.all([
        db.prepare("SELECT * FROM contacts WHERE id=?").bind(keep).first(),
        db.prepare("SELECT * FROM contacts WHERE id=?").bind(drop).first(),
      ]);
      if (!a || !b) return err("Contact not found", 404);
      const m = {};
      for (const k of ["company", "title", "email", "phone", "source"]) m[k] = a[k] || b[k] || "";
      m.tags = tagsIn([...JSON.parse(a.tags || "[]"), ...JSON.parse(b.tags || "[]")]);
      m.notes = [a.notes, b.notes].filter(Boolean).join("\n\n").slice(0, 5000);
      const ts = now();
      await db.batch([
        db.prepare("UPDATE contacts SET company=?,title=?,email=?,phone=?,source=?,tags=?,notes=?,updated_at=? WHERE id=?")
          .bind(m.company, m.title, m.email, m.phone, m.source, m.tags, m.notes, ts, keep),
        db.prepare("UPDATE deals SET contact_id=? WHERE contact_id=?").bind(keep, drop),
        db.prepare("UPDATE tasks SET contact_id=? WHERE contact_id=?").bind(keep, drop),
        db.prepare("UPDATE activities SET contact_id=? WHERE contact_id=?").bind(keep, drop),
        db.prepare("DELETE FROM contacts WHERE id=?").bind(drop),
      ]);
      await logSystem(db, `Merged duplicate "${b.name}" into this contact`, keep);
      return json(contactOut(await db.prepare("SELECT * FROM contacts WHERE id=?").bind(keep).first()));
    }
    if (!id && method === "POST") {
      const f = contactFields(body);
      if (!f.name) return err("Name is required");
      const ts = now();
      const c = { id: uid(), ...f, created_at: ts, updated_at: ts };
      await db.prepare(INSERT_CONTACT).bind(c.id, c.name, c.company, c.title, c.email, c.phone, c.source, c.tags, c.notes, ts, ts).run();
      return json(contactOut(c), 201);
    }
    if (id && method === "PATCH") {
      const cur = await db.prepare("SELECT * FROM contacts WHERE id=?").bind(id).first();
      if (!cur) return err("Not found", 404);
      const f = contactFields({ ...contactOut(cur), ...body });
      if (!f.name) return err("Name is required");
      const ts = now();
      await db.prepare("UPDATE contacts SET name=?,company=?,title=?,email=?,phone=?,source=?,tags=?,notes=?,updated_at=? WHERE id=?")
        .bind(f.name, f.company, f.title, f.email, f.phone, f.source, f.tags, f.notes, ts, id).run();
      return json(contactOut({ ...cur, ...f, updated_at: ts }));
    }
    if (id && method === "DELETE") {
      await db.prepare("DELETE FROM contacts WHERE id=?").bind(id).run();
      return json({ ok: true });
    }
  }

  // ----- deals -----
  if (resource === "deals") {
    const fields = (b) => ({
      title: str(b.title, 160),
      contact_id: str(b.contact_id, 64) || null,
      stage: oneOf(b.stage, STAGES, "lead"),
      value: Math.max(0, num(b.value)),
      probability: b.probability === "" || b.probability === null || b.probability === undefined
        ? null : Math.min(100, Math.max(0, Math.round(num(b.probability)))),
      close_date: isDate(str(b.close_date, 10)) ? str(b.close_date, 10) : "",
      notes: str(b.notes, 5000),
    });
    if (!id && method === "POST") {
      const f = fields(body);
      if (!f.title) return err("Deal name is required");
      const ts = now();
      const d = { id: uid(), ...f, created_at: ts, updated_at: ts, stage_changed_at: ts };
      await db.prepare("INSERT INTO deals (id,title,contact_id,stage,value,probability,close_date,notes,created_at,updated_at,stage_changed_at) VALUES (?,?,?,?,?,?,?,?,?,?,?)")
        .bind(d.id, d.title, d.contact_id, d.stage, d.value, d.probability, d.close_date, d.notes, ts, ts, ts).run();
      const activity = d.contact_id ? await logSystem(db, `Deal created: ${d.title}`, d.contact_id, d.id) : null;
      return json({ ...d, activity }, 201);
    }
    if (id && method === "PATCH") {
      const cur = await db.prepare("SELECT * FROM deals WHERE id=?").bind(id).first();
      if (!cur) return err("Not found", 404);
      const f = fields({ ...cur, ...body });
      if (!f.title) return err("Deal name is required");
      const ts = now();
      const stageChanged = f.stage !== cur.stage;
      const sca = stageChanged ? ts : cur.stage_changed_at;
      await db.prepare("UPDATE deals SET title=?,contact_id=?,stage=?,value=?,probability=?,close_date=?,notes=?,updated_at=?,stage_changed_at=? WHERE id=?")
        .bind(f.title, f.contact_id, f.stage, f.value, f.probability, f.close_date, f.notes, ts, sca, id).run();
      const activity = stageChanged ? await logSystem(db, `${f.title} moved from ${cur.stage} to ${f.stage}`, f.contact_id, id) : null;
      return json({ ...cur, ...f, updated_at: ts, stage_changed_at: sca, activity });
    }
    if (id && method === "DELETE") {
      await db.prepare("DELETE FROM deals WHERE id=?").bind(id).run();
      return json({ ok: true });
    }
  }

  // ----- tasks -----
  if (resource === "tasks") {
    const fields = (b) => ({
      title: str(b.title, 300),
      due_date: isDate(str(b.due_date, 10)) ? str(b.due_date, 10) : "",
      priority: oneOf(b.priority, PRIORITIES, "normal"),
      recurrence: oneOf(b.recurrence, RECURRENCES, "none"),
      contact_id: str(b.contact_id, 64) || null,
      deal_id: str(b.deal_id, 64) || null,
      done: b.done ? 1 : 0,
    });
    if (!id && method === "POST") {
      const f = fields(body);
      if (!f.title) return err("Task needs a title");
      const ts = now();
      const t = { id: uid(), ...f, done: 0, done_at: "", created_at: ts, updated_at: ts };
      await db.prepare(INSERT_TASK).bind(t.id, t.title, t.due_date, t.priority, t.recurrence, t.contact_id, t.deal_id, 0, "", ts, ts).run();
      return json(taskOut(t), 201);
    }
    if (id && method === "PATCH") {
      const cur = await db.prepare("SELECT * FROM tasks WHERE id=?").bind(id).first();
      if (!cur) return err("Not found", 404);
      const f = fields({ ...taskOut(cur), ...body });
      if (!f.title) return err("Task needs a title");
      const ts = now();
      const justDone = f.done && !cur.done;
      const done_at = f.done ? (cur.done_at || ts) : "";
      await db.prepare("UPDATE tasks SET title=?,due_date=?,priority=?,recurrence=?,contact_id=?,deal_id=?,done=?,done_at=?,updated_at=? WHERE id=?")
        .bind(f.title, f.due_date, f.priority, f.recurrence, f.contact_id, f.deal_id, f.done, done_at, ts, id).run();
      let next = null;
      if (justDone && f.recurrence !== "none") {
        next = { id: uid(), ...f, due_date: nextDue(f.due_date, f.recurrence), done: 0, done_at: "", created_at: ts, updated_at: ts };
        await db.prepare(INSERT_TASK).bind(next.id, next.title, next.due_date, next.priority, next.recurrence, next.contact_id, next.deal_id, 0, "", ts, ts).run();
        next = taskOut(next);
      }
      return json({ task: taskOut({ ...cur, ...f, done_at, updated_at: ts }), next });
    }
    if (id && method === "DELETE") {
      await db.prepare("DELETE FROM tasks WHERE id=?").bind(id).run();
      return json({ ok: true });
    }
  }

  // ----- activities -----
  if (resource === "activities") {
    if (!id && method === "POST") {
      const a = {
        id: uid(),
        type: oneOf(body.type, ACTIVITY_TYPES.filter((t) => t !== "system"), "note"),
        body: str(body.body, 5000),
        contact_id: str(body.contact_id, 64) || null,
        deal_id: str(body.deal_id, 64) || null,
        created_at: now(),
      };
      if (!a.body) return err("Write something first");
      await db.prepare("INSERT INTO activities (id,type,body,contact_id,deal_id,created_at) VALUES (?,?,?,?,?,?)")
        .bind(a.id, a.type, a.body, a.contact_id, a.deal_id, a.created_at).run();
      if (a.contact_id) await db.prepare("UPDATE contacts SET updated_at=? WHERE id=?").bind(a.created_at, a.contact_id).run();
      return json(a, 201);
    }
    if (id && method === "DELETE") {
      await db.prepare("DELETE FROM activities WHERE id=?").bind(id).run();
      return json({ ok: true });
    }
  }

  return err("Not found", 404);
}

const SECURITY_HEADERS = {
  "x-content-type-options": "nosniff",
  "x-frame-options": "DENY",
  "referrer-policy": "same-origin",
  "x-robots-tag": "noindex, nofollow",
};

export default {
  async fetch(req, env) {
    const url = new URL(req.url);
    const p = url.pathname;

    if (p === "/api/crm" || p.startsWith("/api/crm/")) {
      try {
        const res = await handleApi(req, env, p.slice("/api/crm".length) || "/");
        for (const [k, v] of Object.entries(SECURITY_HEADERS)) res.headers.set(k, v);
        return res;
      } catch (e) {
        console.error(e);
        return err("Something went wrong on the server", 500);
      }
    }

    if (p === "/crm" || p === "/crm/" || p === "/") {
      return new Response(APP_HTML, {
        headers: { "content-type": "text/html; charset=utf-8", "cache-control": "no-cache", ...SECURITY_HEADERS },
      });
    }
    return new Response("Not found", { status: 404 });
  },
};
