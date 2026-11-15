# Changelog

## 1.1.0

- The installer is no longer built into the image. The image carries only a
  small wrapper (`wrapper.sh`, served as `/bootstrap.sh`) that verifies the
  server's TLS key and then fetches `client/bootstrap.sh` over the pinned
  connection. `client/` is mounted into the container and read on every
  request, so the installer and the key sync can change without a new image,
  a release or a restart.
- **Upgrading from 1.0.x:** the server machine now needs the `client/` folder
  next to `compose.yaml` (the new `compose.yaml` mounts it at `/client`).
- The admin page and the log warn when client scripts are missing.

## 1.0.2

- The payload is now also copied to `~/purrbrews-bootstrap-payload` for the
  user who ran `sudo`, owned by them. Before, it was only in a root-only
  folder they could not open. The entry script still runs from the root-only
  original.

## 1.0.1

- Fix: on machines with a UTF-8 locale the key sync rejected every key that
  had a comment ("zero valid keys"), so bootstrapping failed. The client
  scripts now run in the C locale.

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
