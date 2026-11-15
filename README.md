# purrbrews-bootstrap

[![release](https://github.com/purrMonster/purrbrews-bootstrap/actions/workflows/release.yml/badge.svg)](https://github.com/purrMonster/purrbrews-bootstrap/actions/workflows/release.yml)

A small server that hands SSH public keys to machines and keeps them in step.

You keep one list of public keys on an admin page. A new machine runs a one-line
command, pins the server's TLS key, and from then on pulls the list on a timer.
Add a key and every machine has it by the next sync; remove it and it is gone
everywhere. The admin page also shows which machines are pulling.

It knows nothing about any particular network or fleet: no host names, addresses
or site settings are built in. Everything it remembers lives in one `data/` folder.

```
   admin page (this machine only)                    new machine
   http://localhost:8444                             curl … /bootstrap.sh | sudo bash
   ┌───────────────────────────┐    HTTPS :8443     ┌────────────────────────────────┐
   │ keys · clients · settings │ ◄───────────────── │ 1. pin the server's TLS key    │
   │                           │   pinned TLS key   │ 2. install keys for one user   │
   │ data/  state, TLS key,    │                    │ 3. sync on a timer ────────────┤
   │        admin token,       │                    │ 4. optional: fetch + run the   │
   │        payload/           │                    │    payload                     │
   └───────────────────────────┘                    └────────────────────────────────┘
```

## Run it

**With Docker**, from a released image (`linux/amd64` and `linux/arm64`):

```bash
docker compose up -d
docker compose logs bootstrap      # the admin token and the TLS pin
```

`compose.yaml` runs the release named by `BOOTSTRAP_VERSION` (set it in `.env`
to pin or upgrade). Only `compose.yaml` is needed on the machine that runs it;
no checkout required. Without Compose:

```bash
docker run -d --name purrbrews-bootstrap --restart unless-stopped \
  --user "$(id -u):$(id -g)" -v "$PWD/data:/data" \
  -p 8443:8443 -p 127.0.0.1:8444:8444 \
  ghcr.io/purrmonster/purrbrews-bootstrap:1.0.0
```

On Linux, run the container as the owner of `./data` so the files stay yours:
put `BOOTSTRAP_UID` and `BOOTSTRAP_GID` (`id -u`, `id -g`) in `.env`.

**Built from this checkout** instead of a release:

```bash
docker compose -f compose.yaml -f compose.build.yaml up -d --build
```

**Without Docker** (Python 3 and the `openssl` command; nothing to install):

```bash
python3 server.py
```

Then open <http://localhost:8444> and sign in with the admin token from the log
(it is also in `data/admin-token`).

## Use it

1. **Settings → Server address.** Enter the address clients reach this machine
   on, e.g. `https://192.0.2.10:8443`. The server cannot always work this out
   itself, least of all inside a container.
2. **SSH keys.** Paste the contents of each `.pub` file. Only plain public keys
   are accepted; private keys and lines with options (`command=`, `from=`) are
   refused.
3. **Add a client.** Choose the user whose keys should be managed, copy the
   command, and run it on the new machine. It carries the TLS pin, so the
   machine verifies it is talking to this server before trusting anything.
4. **Clients.** Each machine appears once it has pulled the keys. *Active* means
   it pulled within two sync intervals; *Pending* means the key list changed
   since its last pull.

To start with keys already in place, put an `authorized_keys` file in `data/`
before the first start; it is imported once.

## What happens on a client

`bootstrap.sh` (needs root, `bash`, and `curl` + `openssl`, which it installs if
it can):

- pins the server's TLS public key. With `PB_PIN=…` in the command (the admin
  page includes it) the check is strict; without it, it shows the pin and asks.
- writes `/etc/purrbrews-bootstrap/client.conf` and installs
  `/usr/local/sbin/purrbrews-bootstrap-sync`.
- syncs the keys into a marked block in the user's `~/.ssh/authorized_keys`.
  Lines outside the block are never touched.
- schedules the sync: a systemd timer, or `/etc/cron.d` where there is no systemd.

The sync is fail-safe. If the server is unreachable it changes nothing and exits
`75` (not a failure). If a different TLS key answers, or the server returns no
valid keys, it changes nothing and fails loudly. An outage never looks like
"revoke everything".

Options: `--user NAME`, `--name NAME`, `--skip-keys`, `--yes`, and `--` followed
by arguments for the payload's entry script.

To remove it from a client: disable `purrbrews-bootstrap-sync.timer` (or delete
`/etc/cron.d/purrbrews-bootstrap-sync`), delete `/etc/purrbrews-bootstrap` and the
sync script, and remove the marked block from `authorized_keys`.

## Payload (optional)

Files in `data/payload/` are offered to clients at `/files/…` with a
`SHA256SUMS` list. After key setup, `bootstrap.sh` downloads them to
`/var/lib/purrbrews-bootstrap/payload`, checks every file, and, if you chose an
entry script under Settings, runs it with:

| Variable | Meaning |
|---|---|
| `BOOTSTRAP_URL` | this server's address |
| `BOOTSTRAP_PIN` | the TLS pin the client verified |
| `BOOTSTRAP_CLIENT` | the client's name |
| `BOOTSTRAP_PAYLOAD_DIR` | where the payload was downloaded |

This is how a project hangs its own machine setup off the bootstrap without the
server knowing anything about it. To serve a folder from another project, set
`BOOTSTRAP_PAYLOAD=/path/to/folder` in `.env` (Docker), or copy it into
`data/payload/`.

**The payload is public.** Anyone who can reach the client port can download it.
Never put passwords, tokens or private keys in it.

## Security

- **The admin page decides which SSH keys every client trusts.** That is the
  thing to protect. It listens on loopback only, needs the admin token, refuses
  requests addressed to any other host name, and only accepts changes from its
  own page. To reach it from another machine, use an SSH tunnel
  (`ssh -L 8444:localhost:8444 server`) rather than publishing the port.
- **Nothing on the client port is secret:** public keys, the scripts in
  `client/`, and the payload. It is read-only; no request there can change the
  key list.
- **Clients trust the server by its pinned TLS key,** not a certificate
  authority. The key is created on first start and kept in `data/certs/`. If
  you delete it, every client refuses the server until re-bootstrapped.
- **The client list is for visibility, not access control.** Names and
  identities are reported by the clients themselves and could be faked by
  anyone on the network. Do not treat an entry as proof.
- **Whoever controls this server controls SSH access to every client.** Keep the
  machine it runs on, and its `data/` folder, as safe as the keys themselves.
- **Back up `data/`.** It is the whole state: restore it and clients carry on
  without noticing.

## Settings

Everything is optional. With Docker, put these in `.env` (see `.env.example`).

| Variable | Default | Meaning |
|---|---|---|
| `BOOTSTRAP_PORT` | `8443` | client port (HTTPS) |
| `BOOTSTRAP_BIND` | `0.0.0.0` | address the client port listens on |
| `BOOTSTRAP_ADMIN_PORT` | `8444` | admin port (HTTP) |
| `BOOTSTRAP_ADMIN_BIND` | `127.0.0.1` | address the admin port listens on (without Docker) |
| `BOOTSTRAP_ADMIN_HOSTS` | | extra host names the admin page answers to, comma-separated |
| `BOOTSTRAP_ADMIN_TOKEN` | generated | use your own admin token (16+ characters) |
| `BOOTSTRAP_PUBLIC_URL` | | initial server address, instead of setting it on the page |
| `BOOTSTRAP_DATA` | `./data` | where state is kept (without Docker) |
| `BOOTSTRAP_PAYLOAD` | `./data/payload` | folder served as the payload (Docker) |

## Releases

The `VERSION` file is the version. A release is a git tag `vX.Y.Z` that matches
it; pushing the tag makes GitHub Actions run the tests, build the image for
both architectures, push it to the GitHub Container Registry as `X.Y.Z`, `X.Y`,
`X` and `latest`, and create the GitHub release.

```bash
# add a "## 1.1.0" section to CHANGELOG.md and commit it, then:
bash scripts/release.sh 1.1.0     # sets the version, runs the tests, commits, tags
git push origin HEAD v1.1.0       # publishes
```

The image is named after the repository (`ghcr.io/<owner>/<repo>`), so a fork
publishes under its own name; point `BOOTSTRAP_IMAGE` at it. A new package on
the registry starts private: make it public in the package settings if hosts
should pull it without logging in.

To upgrade a running server, set the new `BOOTSTRAP_VERSION` and run
`docker compose up -d`. State lives in `data/`, so clients notice nothing.

## Layout

```
VERSION              the release version (the tag must match)
server.py            the server (Python standard library only)
web/admin.html       the admin page
client/bootstrap.sh  what a new machine runs
client/sync.sh       the key sync installed on each machine
compose.yaml         run a released image;  compose.build.yaml  build locally
scripts/release.sh   cut a release
.github/workflows/   ci.yml (tests on every push), release.yml (publish on a tag)
tests/               end-to-end checks:  python3 -m unittest discover -s tests
data/                created at first start; never committed
```
