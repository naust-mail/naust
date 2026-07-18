# Contributing

Contributions are welcome. Naust is an actively developed hard fork of Mail-in-a-Box with a specific direction - read this guide before sending a PR to avoid wasted effort.

## Project direction

This project replaces the PHP/Nextcloud stack with modern alternatives (Rav webmail, FileBrowser, Radicale), a Go control-plane daemon, a Vue 3 admin UI, and WebAuthn. The mail core - Postfix, Dovecot, NSD - is intentionally stable and conservative.

**Good contributions:**
- Bug fixes with a clear reproduction
- Hardening and security improvements
- Compatibility fixes for supported Ubuntu versions (22.04, 24.04, 26.04)
- Admin UI improvements (Vue 3, `frontend/`)
- Docker stack improvements
- Documentation

**Out of scope:**
- Reintroducing PHP, Nextcloud, Roundcube, or Z-Push
- Adding new external services without a strong case
- Changes that break idempotency of setup scripts

## Development setup

### Prerequisites

- Python 3.10+
- [Docker](https://docs.docker.com/get-docker/) with Compose (`docker compose version`)
- Go 1.22+ (for control-plane daemon work only)
- [Bun](https://bun.sh) (for admin UI work only)

### Quickstart

```bash
git clone https://github.com/naust-mail/naust.git
cd naust
python3 setup/boxctl docker    # interactive Docker setup wizard
```

Or manually:

```bash
cp deploy/docker/.env.example deploy/docker/.env
# set PRIMARY_HOSTNAME in .env

docker compose -f deploy/docker/docker-compose.yml \
  --profile rav --profile filebrowser --profile radicale --profile monitoring \
  up --build
```

The admin panel is at `https://localhost:8443/admin`. The initial admin account is configured during the first-run wizard.

### Iterating on a single component

Rebuild one container without restarting the stack:

```bash
docker compose -f deploy/docker/docker-compose.yml --profile rav up --build -d webmail
```

To pick up a change to a `setup/components/defs/*.py` component, re-run the installer -
it's idempotent, so only the changed component actually re-applies:

```bash
sudo setup/install.sh
```

### Admin UI (Vue 3)

The frontend lives in `frontend/` and is built separately from the setup scripts:

```bash
cd frontend
bun install
bun run dev      # dev server with hot reload - proxies API to the control-plane daemon
bun run build    # production build, output to dist/admin, served statically by nginx
```

The admin UI talks to the Go control-plane daemon (`managerd`) at `https://<box>/admin/api/`. In dev mode, Vite proxies API calls to the running Docker daemon container.

## Codebase layout

```
daemon/            # Go control-plane daemon (managerd)
  internal/
    auth/           # password hashing, sessions, WebAuthn
    httpapi/        # REST API served under /api
    checks/         # system status checks
    ...

setup/
  components/
    defs/           # one Python module per component (TLS, Postfix, rspamd, webmail
                     # clients, FileBrowser, Radicale, monitoring, system, ...) -
                     # doit-based, must be idempotent
  boxctl/           # interactive setup wizard (Python TUI)
  conf/
    nginx/          # nginx config templates
    dovecot/        # Dovecot config templates, versioned by dialect
    fail2ban/       # jails and filters
    systemd/        # service unit files

frontend/            # Vue 3 + Vite + TypeScript admin UI
  src/
    pages/            # one file per admin panel page
    components/       # shared components
    stores/           # Pinia stores
    composables/       # API hooks

deploy/
  docker/            # Dockerfiles, compose files, entrypoints

tests/               # Python component tests (pytest) - setup/components, boxctl,
                     # control socket, tools. Go tests live alongside their packages
                     # under daemon/ (*_test.go).
```

All setup scripts are **idempotent** - running them more than once must be safe. This is a hard requirement.

## Commit style

- One commit per logical change. Large features should be split by subsystem (e.g. separate commits for backend wiring, nginx config, and UI).
- Commit messages: short imperative title, blank line, then a brief explanation of *why* if the change isn't obvious.
- No "Co-Authored-By" trailers.

## Pull requests

Use the PR template. At minimum, describe what changed and how you tested it (Docker, bare metal, or neither - all are fine, just be honest).

Setup script changes should be tested with a full Docker stack run. Changes to `daemon/` or `frontend/` can be tested with the Docker daemon container alone.

## Tests

Run the Python component test suite from the repo root:

```bash
pytest tests/
```

Run the Go daemon test suite:

```bash
cd daemon && go test ./...
```

Both suites must pass before a PR is merged. Contributions that add coverage are welcome.

## License

This project is licensed under the [MIT License](../LICENSE). By submitting a pull request you agree to license your contribution under MIT.

## Code of Conduct

This project has a [Code of Conduct](CODE_OF_CONDUCT.md).
