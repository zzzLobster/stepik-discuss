# Plans tracker (normative per planning rules)

- Plans live in `plans/` as `NNNN-topic.md` (e.g. `0002-pwa-notifications.md`).
- Status lifecycle: `DRAFT` → `REFINED` → `FINAL` (mutual approval). `FINAL` is immutable — any change after `FINAL` requires a new plan file.
- Every plan must note all data source references used to design the solution (see §14 in each plan).

| Plan | Topic | Status | Updated | Notes |
|------|-------|--------|---------|-------|
| `0001-stepik-discussion-site.md` | Discussion site (Gate + Caddy + remark42, hybrid C auth) | REFINED | 2026-09-20 | Parent spec; §7.4 PWA hook implemented by 0002; refresh-token addendum 2026-09-20 |
| `0002-pwa-notifications.md` | PWA wrapper + Web Push new-comment notifications | REFINED 2026-09-22, ready for implementation (D0→D1→D2→D3) | 2026-09-22 | Q1–Q7 + minors resolved 2026-09-22 (teacher: ok); D1/D2 gated on D0 verdict; full source list in §14; NOT `FINAL` yet |
| `0003-teacher-telegram.md` | Teacher Telegram channel (deferred) | DESIGNED, DEFERRED | 2026-09-21 | Implement after 0002 P2 green; needs BotFather token |
