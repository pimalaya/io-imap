---
cairn: tasks
change: a-wrong-weekday-keeps-its-date
---

# Tasks

- [x] src/rfc5256/sort.rs: regression tests failing on the current code, the key of a wrong weekday and the fallback sort of such a message (`rfc5256::sort::tests::date_sort_key_ignores_a_wrong_weekday`, `fallback_date_ignores_a_wrong_weekday`)
- [x] src/rfc5256/sort.rs: `date_sort_key` drops the day-of-week before parsing; an unparsable header still yields `None`
- [x] CHANGELOG under [Unreleased]
- [x] Fold the delta into cairn/spec, log, land
