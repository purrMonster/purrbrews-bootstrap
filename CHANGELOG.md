# Changelog

## 1.0.0

First release.

- Server with two listeners: a pinned HTTPS port for clients and a
  loopback-only admin port.
- Admin page: manage SSH public keys, see which clients are pulling them, build
  the command for a new client, settings.
- Client `bootstrap.sh` and key sync (systemd timer or cron), with a managed
  block in `authorized_keys` and fail-safe behaviour.
- Optional payload: serve a folder to clients, checksummed, and run one script
  from it.
- Image published for `linux/amd64` and `linux/arm64`.
