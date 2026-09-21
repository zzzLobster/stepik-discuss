# 0003 — Teacher Telegram channel for new comments (DEFERRED)

Date: 2026-09-21
Status: DESIGNED, DEFERRED — implement after plan 0002 (PWA + WebPush) is green. No code changes until teacher provides bot token.
Parent: `plans/0002-pwa-notifications.md` §13 decision 3 (teacher Telegram channel designed here, postponed from 0002 MVP).

## 1. Goal

Teacher (single admin, `TEACHER_ID=1182644732`) gets a **Telegram message for every new comment** across all owned classes, without opening the site. Students keep WebPush only (0002) — no Telegram for students (no IDs collected, minors/152-FZ safe).

Non-goals: student Telegram notify (`NOTIFY_USERS=telegram` — rejected, needs per-student Telegram IDs we must not collect); Telegram login (`AUTH_TELEGRAM` — rejected, Gate Stepik-OAuth only); reply-from-Telegram (read-only alerts, moderation stays in `/discuss/admin/`).

## 2. Ground truth (remark42-native, verified in docs)

- remark42 `v1.16.4` supports `NOTIFY_ADMINS=telegram|slack|webhook|email` (multi, comma-separated) via `go-pkgz/notify`. Admin Telegram needs: `TELEGRAM_TOKEN=<bot-token>` + `NOTIFY_ADMINS=telegram` (+ `webhook` alongside for 0002 fan-out: `NOTIFY_ADMINS=webhook,telegram`) + `NOTIFY_TELEGRAM_CHAN=<dest>` + `NOTIFY_QUEUE` (shared with webhook, bump to 200 in 0002 already covers it).
- Destination options: private channel / group (bot as Administrator with Post permission) or teacher's numeric user ID (via `@myidbot`). Recommended: **private channel** (history + multi-device + no token-in-DM leakage), teacher subscribed alone.
- Formatting limits: Telegram API strips most HTML — remark42 converts `h1-h6` → `<b>`, truncates. Snippet = rendered comment text, plain. No avatars, no deep-link buttons in MVP (plain `page_url` text link).
- Zero Gate involvement on the hot path: remark42 → `https://api.telegram.org` directly (egress 443). Gate WebPush pipeline (0002 §7) untouched; both fire per comment independently.

## 3. Architecture (delta to 0002, no new containers)

```
Student posts ──▶ Caddy /discuss/* ──forward_auth──▶ remark42 :8080
  remark42 ──NOTIFY_ADMINS=webhook──▶ http://gate:8081/push/webhook ──▶ WebPush to all members except author (0002)
  remark42 ──NOTIFY_ADMINS=telegram──▶ https://api.telegram.org/bot<token>/sendMessage ──▶ private channel ──▶ teacher phone/desktop
```

- Coexistence: `NOTIFY_ADMINS=webhook,telegram` fires both notifiers per comment (queue shared, failures isolated — webhook timeout never blocks telegram and vice versa, per `go-pkgz/notify` fan-out).
- Network: needs VPS egress 443 to `api.telegram.org` (RU VPS — verify reachability; if blocked/slow, fallback is WebPush-only + email digest, decided at implementation time with `curl -w ttfb` evidence in TESTLOG).
- Secrets: `TELEGRAM_TOKEN` + `NOTIFY_TELEGRAM_CHAN` in VPS `deploy/.env` only (`chmod 600`), keys only in `deploy/.env.example`. Token created by teacher via BotFather (see §5). Never in repo, never in logs (hash-compare debug only).

## 4. Config delta (frozen, apply at implementation time)

`deploy/compose.yml` remark42 env (additive to 0002):

| Key | Value / note |
|-----|--------------|
| `TELEGRAM_TOKEN` | `${TELEGRAM_TOKEN}` (BotFather token, VPS `.env` only) |
| `NOTIFY_ADMINS` | `webhook,telegram` (was `webhook` in 0002) |
| `NOTIFY_TELEGRAM_CHAN` | `${NOTIFY_TELEGRAM_CHAN}` (private channel numeric ID, e.g. `-100…`, or `@name` for public — private recommended) |
| `NOTIFY_QUEUE` | `200` (already set in 0002, shared) |

`deploy/.env.example`: keys only (`TELEGRAM_TOKEN=`, `NOTIFY_TELEGRAM_CHAN=` + comment `# from BotFather / channel ID, VPS .env only`).

No Caddy, Gate, Cloudflare, or BoltDB changes. No new deps. Resource limits unchanged.

## 5. Teacher setup (you do, 10 min, once)

1. Telegram → `@BotFather` → `/newbot` → name e.g. `Stepik Discuss Alerts` → username must end in `bot` → copy token → VPS `.env` `TELEGRAM_TOKEN=<token>`.
2. Create **private channel** (e.g. `Stepik Discuss Alerts`) → add bot as **Administrator** (Post messages permission) → get channel numeric ID (forward any channel message to `@JsonDumpBot` / `@myidbot`, take `forward_from_chat.id`) → VPS `.env` `NOTIFY_TELEGRAM_CHAN=<id>`.
3. On VPS: `docker compose up -d remark42` → post test comment as student → teacher channel receives message <60s. Paste evidence (timestamp + `docker compose logs remark42 | grep -i telegram`) into `TESTLOG.md` Wave T1.
4. Revoke/rotate: BotFather `/revoke` → update VPS `.env` → `up -d remark42`. Old token dies immediately.

## 6. Message shape (remark42 default, no template override in MVP)

Per comment: `💬 <Site stepik-discuss> <Page https://stepik.study67.fyi/class/<cid>>\n<Author stepik_<uid> (<FIO>)>:\n<Text snippet, Telegram-formatted>` + timestamp. Author is Gate-minted `stepik_<id>` (attributed per 0001 §6.1 D0 verdict). No auth cookies, no JWT, no tokens in message. Deleted/edited comments do not edit Telegram messages (append-only alerts — accepted).

Privacy note (minors/152-FZ): channel contains student names + comment text — same data members already see on-page (no new disclosure class), but new copy at rest in Telegram cloud. Mitigations: private channel (invite-only, teacher alone), no forwarding, retention = Telegram default (manual delete on request / `deleteme` parity — document in runbook at implementation). Consent line (0002 §9) already covers notification channels generally; extend with `…в том числе преподавателю в Telegram` at implementation time (teacher approves copy then).

## 7. Test plan (Wave T1, append to TESTLOG.md, after 0002 P2 green)

1. Student posts in `/class/87566` → teacher channel message arrives <60s with correct `cid` link + author + snippet; WebPush to other students still fires (both notifiers).
2. Teacher posts own comment → channel still fires (admin gets own posts too — remark42 semantics; filter later if noisy).
3. Two rapid comments → two Telegram messages (no coalesce — unlike WebPush 30s window; accepted, teacher volume <20 users).
4. Bad token (`TELEGRAM_TOKEN=invalid`) → remark42 logs `telegram send failed`, webhook/WebPush unaffected (isolation proof).
5. Rollback: `NOTIFY_ADMINS=webhook` + `up -d remark42` → Telegram stops, WebPush continues.

## 8. Risks / deferred notes

- Telegram API reachability from RU VPS (egress filter / throttling) — verify with `curl` at implementation; fallback stays WebPush-only.
- Channel ID is sensitive-ish (spam target if leaked) — treat like secret (VPS `.env` only).
- No quiet hours in MVP per 0002 §13 decision 2 — teacher night noise accepted at this scale; revisit with digest/quiet-hours design only if requested (new plan, not here).
- Cost: zero (Bot API free); no new containers, RAM, or deps.

## 9. Build (when un-deferred, 0.5d)

1. Teacher does §5 steps 1–2 (token + channel ID into VPS `.env`).
2. Dev: compose `.env.example` keys + remark42 env rows (§4) → `docker compose config` must parse → `caddy-verify.sh` re-run (no Caddy change expected, contract guard).
3. Deploy: `docker compose up -d remark42` → Wave T1 (§7) → TESTLOG evidence → merge.
