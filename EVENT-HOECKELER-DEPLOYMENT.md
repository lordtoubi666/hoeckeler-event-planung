# event.hoeckeler.ch deployment

The public frontend is hosted by GitHub Pages:

- Frontend: https://event.hoeckeler.ch
- API/backend: https://api.event.hoeckeler.ch
- Database: private PostgreSQL Docker volume

GitHub Pages only hosts HTML/CSS/JavaScript. `server.py` and PostgreSQL must run on your Docker server.

## 1. GitHub repository

Push this project to GitHub and use `main` for production.

Repository → Settings → Pages:
- Source: **GitHub Actions**
- Custom domain: `event.hoeckeler.ch`
- After the certificate is issued, enable **Enforce HTTPS**

The included workflow `.github/workflows/deploy-pages.yml` deploys `static/` whenever `main` changes and writes the correct CNAME/config automatically.

## 2. DNS

At the DNS provider for `hoeckeler.ch` create:

### Frontend / GitHub Pages
- Type: `CNAME`
- Name/Host: `event`
- Value/Target: `YOUR-GITHUB-USER.github.io`

Do not point the CNAME to a repository path.

### Backend API
- Type: `A`
- Name/Host: `api.event`
- Value: your public Docker-server IPv4 address

If the server has a stable IPv6 address you can additionally create an AAAA record.

## 3. Firewall / NAT

The Docker/Caddy server needs inbound TCP:
- 80
- 443

Forward those ports to the Docker host if it is behind NAT.

Do NOT expose:
- PostgreSQL 5432
- application port 8080

## 4. Backend

Copy:
```bash
cp .env.event.example .env.event
```

Replace all placeholder secrets. Generate strong values, for example:
```bash
openssl rand -hex 32
openssl rand -base64 36
```

Start:
```bash
docker compose --env-file .env.event -f docker-compose.event.yml up -d --build
```

Check:
```bash
docker compose --env-file .env.event -f docker-compose.event.yml ps
curl https://api.event.hoeckeler.ch/api/health
```

## 5. GitHub Pages

Push `main`. GitHub Actions deploys the frontend.

Then test:
- https://event.hoeckeler.ch
- login
- create/edit a test event
- logout/login
- PWA install
- Excel/backup downloads

## 6. Existing production data

The compose file uses:
`hoeckeler_event_planner_prod_postgres`

If upgrading an existing installation, inspect the existing Docker volume before starting:
```bash
docker volume ls
```

Never use `docker compose down -v` if the existing data must be retained.

## 7. Security notes

The browser sends login credentials directly from `event.hoeckeler.ch` to the HTTPS API at `api.event.hoeckeler.ch`; GitHub Pages does not run or store the Python backend.

The backend only permits browser CORS requests from:
`https://event.hoeckeler.ch`

Keep `.env.event` out of Git and never put database, SMTP, SMS or application secrets in the GitHub Pages files.
