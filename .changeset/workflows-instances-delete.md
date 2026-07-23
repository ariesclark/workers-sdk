---
"wrangler": minor
"miniflare": minor
---

Add a workflow instance deletion command and local development support.

- `wrangler workflows instances delete <name> <id..>` deletes one or up to 100 workflow instances remotely or in local development with `--local`.
- Local development now supports the existing `env.MY_WORKFLOW.get(id).delete()` and `env.MY_WORKFLOW.deleteBatch(instanceIds)` runtime APIs.
