# Operator onboarding

The dashboard `/setup` page is the first-run control surface. It combines live
database, Redis, worker, authentication, inventory, backup, and restore signals
into one ordered checklist. It reports only facts the deployment can gather;
it does not ask an operator to copy values between GitHub, Docker, or the
dashboard.

The backend endpoint is `GET /api/dashboard/onboarding` (proxied by
`GET /api/onboarding`). Required steps are marked `ready`, `action`, or
`blocked`; optional runtime discovery and deferred external integrations are
shown separately. The first useful path is:

1. Confirm PostgreSQL, Redis, and a Celery worker are ready.
2. Open Scan history and run a public image or an image from a configured
   private registry.
3. Enable explicit backup execution only after reviewing its destination.
4. Configure an isolated restore admin URL and verify recovery from Operations.

GitHub publication, deployment observation, and external alert delivery remain
deferred and are intentionally labeled as such instead of blocking local
scanning.
