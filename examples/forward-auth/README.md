# Example: sign-in with Traefik and Authelia

This puts [Traefik](https://traefik.io/) and [Authelia](https://www.authelia.com/) in front of the
Compose stack, so the dashboard needs a signed-in user. Use it to try sign-in locally, or as a starting
point for your own setup. The design is in [docs/design/forward-auth.md](../../docs/design/forward-auth.md).

```text
browser ─▶ Traefik :8443 ─forward-auth─▶ Authelia (users.yml)
              │ copies Remote-User / Remote-Groups / Remote-Email from Authelia, replacing any the
              │ client sent, and adds x-dashboard-proxy-secret
              ▼
           dashboard (no published port) ─▶ API (maps groups to roles)
```

## Run it

From the repository root, with the stack's own `.env` in place:

```bash
docker compose --env-file .env --env-file examples/forward-auth/example.env \
  -f docker-compose.yml -f examples/forward-auth/docker-compose.yml up -d
```

Open <https://scrutineering.localhost:8443>. Browsers resolve `*.localhost` to your own machine. Traefik
serves its built-in self-signed certificate, so your browser warns once for each of the two hosts;
accept it for this local test.

Test users (example only):

| User | Password | Group | Role |
|---|---|---|---|
| `alice` | `example-ksc3NHQtlY0Y` | `scrutineering-security` | `security-operator` |
| `bob` | `example-DBzkUblSp0E2` | `family` | none: sees "No access yet" |

What to look for in the browser:

1. Signed out, any page sends you to the Authelia login.
2. As `alice`, the header shows `security-operator · alice@scrutineering.localhost` and **Sign out**.
   Audit entries for her actions name `alice` and record her email.
3. **Sign out** ends the session at Authelia and returns to the login.
4. As `bob`, the dashboard shows **No access yet**.

To go back to the plain stack: `docker compose up -d` (recreates the dashboard and API without the
overlay), then `docker compose -f docker-compose.yml -f examples/forward-auth/docker-compose.yml rm -sf
traefik authelia`.

## Making it your own

- **Secrets:** generate new values for everything in `example.env`, and keep them out of git.
- **Users:** replace `authelia/users.yml`. Hash a password with
  `docker run --rm authelia/authelia:4.38.17 authelia crypto hash generate argon2`.
- **Roles:** set `DASHBOARD_GROUP_ROLES` to map your groups, for example
  `ops=operator,security=security-operator`. A user whose groups map to no role is refused.
- **Two-factor:** change `policy: one_factor` to `two_factor` in `authelia/configuration.yml` for anything
  reachable from the internet.
- **Your domain and a real certificate:** replace `scrutineering.localhost` in both config files and give
  Traefik a certificate (for example its Let's Encrypt resolver).
- **Only through Traefik:** the overlay removes the dashboard's published port. Keep it that way, and don't
  publish the API port either (`PYTHON_API_PORT`) on a host others can reach.

## How it was tested

These were checked with curl through Traefik (`-k` for the self-signed certificate), with the stack and
this overlay running:

- signed out: every page and `/api` route redirects to the login, including requests carrying forged
  `Remote-User`, `Remote-Groups` or `x-dashboard-proxy-secret` headers;
- `alice` gets `security-operator`, and forged `Remote-User: bob` / `Remote-Groups: admins` headers
  on her requests are replaced with Authelia's;
- a cross-site POST is refused even when signed in;
- `bob` is refused with `no_role`;
- the dashboard's port is not reachable from the host.

The browser steps above were not automated, because the browser tools stop at the certificate warning.
