# Local config (.env)

SecureScan auto-loads a user-scoped `.env` file at backend startup so
you can persist scanner credentials and other secrets between
reboots without re-exporting them every shell session.

Introduced in v0.6.1.

<!-- toc -->

## Path

```text
$XDG_CONFIG_HOME/securescan/.env

(falls back to)

~/.config/securescan/.env
```

The file is optional. If it does not exist, the startup loader is a
no-op.

## What goes in it

Anything that you'd otherwise `export` in your shell. The most
common cases:

```bash
# ~/.config/securescan/.env

# ZAP daemon credentials
SECURESCAN_ZAP_ADDRESS=http://127.0.0.1:8090
SECURESCAN_ZAP_API_KEY=zap-api-key-from-zap-ui

# Groq API key for AI enrichment
SECURESCAN_GROQ_API_KEY=gsk_...your-key...

# Override the SQLite DB location
SECURESCAN_DB_PATH=/var/lib/securescan/scans.db
```

Any [config var](./configuration.md) is fair game. Auth-related vars
(`SECURESCAN_API_KEY`, `SECURESCAN_AUTH_REQUIRED`,
`SECURESCAN_EVENT_TOKEN_SECRET`) work too — but you almost certainly
want those in a secrets manager / systemd env file, not a dotfile.

## Precedence

```text
shell environment   (highest priority — wins)
~/.config/securescan/.env
(unset = use built-in default)
```

If both the shell and the file set the same variable, the shell
wins. This makes ad-hoc overrides easy without editing the file:

```bash
$ cat ~/.config/securescan/.env
SECURESCAN_ZAP_ADDRESS=http://127.0.0.1:8090

# Override for one run:
$ SECURESCAN_ZAP_ADDRESS=http://10.0.0.5:8090 securescan scan https://staging --type dast
```

## Format

Standard `.env` syntax:

- `KEY=value` per line.
- `#` starts a comment.
- Whitespace around `=` ignored.
- Values are read literally — quoting is preserved (so don't quote
  unless the *value* needs the quotes).

```bash
# Good
SECURESCAN_ZAP_API_KEY=abc123def456

# Wrong (the quotes become part of the key)
SECURESCAN_ZAP_API_KEY="abc123def456"
```

## Permissions

```admonish important
The file commonly contains secrets (ZAP API key, Groq token,
maybe a SecureScan API key). Lock it down:

​    chmod 600 ~/.config/securescan/.env

Anything more permissive will leak credentials to other users on
the host.
```

The loader does **not** enforce permissions — that's your operator's
responsibility. A future release may add a startup warning.

## Container deploys

In containers, mount the file as a volume:

```bash
docker run --rm -p 8000:8000 \
  -v ~/.config/securescan:/root/.config/securescan:ro \
  -e SECURESCAN_API_KEY="$(cat /run/secrets/securescan-api-key)" \
  ghcr.io/metbcy/securescan:v0.10.3 \
  serve --host 0.0.0.0 --port 8000
```

Mount **read-only** (`:ro`); the backend never writes to the file,
and read-only mounts prevent a compromised process from rewriting
secrets back in place.

For Kubernetes, prefer a `Secret` mounted as files:

```yaml
volumes:
  - name: securescan-config
    secret:
      secretName: securescan-env-file
      items:
        - key: .env
          path: .env
volumeMounts:
  - name: securescan-config
    mountPath: /root/.config/securescan
    readOnly: true
```

## Verifying it loaded

The backend logs each loaded var (key only, never the value) at
INFO on startup:

```text
INFO  securescan.config_loader  loaded SECURESCAN_ZAP_ADDRESS from /home/me/.config/securescan/.env
INFO  securescan.config_loader  loaded SECURESCAN_GROQ_API_KEY from /home/me/.config/securescan/.env
INFO  securescan.config_loader  loaded SECURESCAN_DB_PATH from /home/me/.config/securescan/.env
```

A line per var that was actually set from the file (i.e. not
already in the shell environment).

## Source

- Loader:
  [`backend/securescan/config_loader.py`](https://github.com/Metbcy/securescan/blob/main/backend/securescan/config_loader.py)
- Tests:
  [`backend/tests/test_config_loader.py`](https://github.com/Metbcy/securescan/blob/main/backend/tests/test_config_loader.py)

## Next

- [Configuration reference](./configuration.md) — every supported variable.
- [Production checklist](./production-checklist.md) — persistence is on it.
