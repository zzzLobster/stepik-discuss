# Plans tracker (normative per planning rules)

- Plans live in `plans/` as `NNNN-topic.md` (e.g. `0002-pwa-notifications.md`).
- Status lifecycle: `DRAFT` → `REFINED` → `FINAL` (mutual approval). `FINAL` is immutable — any change after `FINAL` requires a new plan file.
- Every plan must note all data source references used to design the solution (see §14 in each plan).

| Plan | Topic | Status | Updated | Notes |
|------|-------|--------|---------|-------|
| `0001-stepik-discussion-site.md` | Discussion site (Gate + Caddy + remark42, hybrid C auth) | REFINED | 2026-09-20 | Parent spec; §7.4 PWA hook implemented by 0002; refresh-token addendum 2026-09-20 |
| `0002-pwa-notifications.md` | PWA wrapper + Web Push new-comment notifications | FINAL | 2026-09-22 | Q1–Q7 + minors resolved 2026-09-22 (teacher: ok); full source list in §14. D0 verdict (2026-09-22, moved here from the plan file to keep FINAL immutable): `webpush-go v1.4.0` live API verified (`GenerateVAPIDKeys` → 32B private + 65B `0x04…` public `RawURLEncoding`, `fp8=hex(sha256(pub string))[:8]`, `SendNotificationWithContext` with `Options{Subscriber mailto:, TTL 86400, Topic class-<cid>, Urgency normal}`) + live remark42 `v1.16.4` webhook notifier with frozen §7.1 template (`NOTIFY_ADMINS=webhook`, `NOTIFY_WEBHOOK_URL=http://gate:8081/push/webhook`, `Content-Type:application/json,X-Push-Webhook-Secret`, `TIMEOUT 5s`, `QUEUE 200`, template with `escapeJSONString` unquoted + `Timestamp.Unix` numeric + `Orig`/`Text` + `ID/ParentID/User.ID/User.Name/Locator.SiteID/Locator.URL/Score`) proves valid JSON on quotes/newlines/emoji, numeric `created_unix`, `Orig` populated, secret headers received, 3+ `comment.ID` matched `^[A-Za-z0-9_-]{1,64}$`, DOM anchor `/#remark-<id>` confirmed; desktop `201` + visible notification recorded (iOS-HS deferred to P2); template string locked, gates D1. D0→D3 implemented 2026-09-22, see git log. |
| `0003-teacher-telegram.md` | Teacher Telegram channel (deferred) | DESIGNED, DEFERRED | 2026-09-21 | Implement after 0002 P2 green; needs BotFather token |
