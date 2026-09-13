# v45 deployment guide

## Architecture

Production:
- `https://planung.example.ch` → Caddy → Python app → production PostgreSQL.
- The Python app serves both the frontend and API, so production is same-origin.

Test:
- GitHub Pages serves only the static frontend from the `develop` branch.
- Prefer a GitHub Pages custom domain such as `https://test-planung.example.ch`.
- The Pages frontend calls `https://test-api.example.ch`.
- The test API uses a completely separate PostgreSQL database and Docker volume.
- `TEST_MODE=true` adds `[TEST]` to email subjects and can redirect email/SMS to fixed test recipients.

## 1. Create the GitHub repository

Push this folder to a repository with `main` and `develop` branches.

In GitHub:
1. Settings → Pages → Source: **GitHub Actions**.
2. Settings → Secrets and variables → Actions → Variables:
   - `TEST_API_URL=https://test-api.example.ch`
   - optional but recommended: `PAGES_CUSTOM_DOMAIN=test-planung.example.ch`
3. For optional production deployment, add repository secrets:
   - `PRODUCTION_HOST`
   - `PRODUCTION_USER`
   - `PRODUCTION_PATH`
   - `PRODUCTION_SSH_KEY`

`develop` automatically deploys the test frontend to GitHub Pages.
Production deployment is deliberately manual through **Actions → Deploy production → Run workflow**.

## 2. DNS

Create DNS records pointing to the Docker host:
- `planung.example.ch`
- `test-api.example.ch`

Caddy obtains and renews HTTPS certificates automatically when ports 80/443 are reachable.

## 3. Production server

Copy `.env.production.example` to `.env.production` and replace every placeholder.

Generate secrets, for example:
```bash
openssl rand -hex 32
openssl rand -base64 36
```

Start:
```bash
docker compose --env-file .env.production -f docker-compose.production.yml up -d --build
```

Do not expose PostgreSQL to the Internet.

## 4. Test backend

Copy `.env.test.example` to `.env.test`.

`GITHUB_PAGES_ORIGIN` must be the exact GitHub Pages origin, for example:
`https://my-org.github.io`

Start the test backend on a host reachable as `TEST_API_DOMAIN`.

If production and test share one server, use one Caddy instance in front of both stacks rather than binding two independent Caddy containers to the same 80/443 ports. The included test compose maps Caddy to 8082/8443 to avoid collision; for a public `test-api` hostname, merge the test reverse-proxy block into your main Caddy instance.

## 5. Git workflow

- Feature branches → Pull Request → `develop`
- `develop` → automated validation + GitHub Pages test frontend
- Test changes
- Merge `develop` → `main`
- Run the manual production deployment workflow

## 6. Cross-origin authentication

The test backend is configured with:
- `COOKIE_SECURE=true`
- `CROSS_SITE_COOKIES=true`
- exact `CORS_ALLOWED_ORIGINS`
- credentialed browser requests
- per-session CSRF token for modifying requests

Do not use `*` as a CORS origin.

## 7. Backups

Run:
```bash
./scripts/backup-postgres.sh
```

The included script keeps 30 days locally. For production, copy backups to a second machine/object store as well. Test restore procedures before relying on the backups.

## Upgrade warning

Older releases used the Docker volume name `hoeckeler_event_planner_postgres`.
v45 production uses `hoeckeler_event_planner_prod_postgres`.

If upgrading an existing installation, identify the actual existing volume with:
```bash
docker volume ls
```
and migrate it before starting the new production stack. Never use `docker compose down -v` on a system whose data must be preserved.

## Recommended GitHub Pages domain setup

For authentication reliability, the recommended test layout is:

```text
test-planung.example.ch  -> GitHub Pages
test-api.example.ch      -> your Docker/Caddy host
planung.example.ch       -> production Docker/Caddy host
```

Using a Pages custom domain under the same parent domain as the API avoids modern browser third-party-cookie restrictions that can affect a raw `username.github.io` frontend talking to an unrelated API domain.

Configure `test-planung.example.ch` as the GitHub Pages custom domain and set:
- repository variable `PAGES_CUSTOM_DOMAIN=test-planung.example.ch`
- `GITHUB_PAGES_ORIGIN=https://test-planung.example.ch`
- repository variable `TEST_API_URL=https://test-api.example.ch`
