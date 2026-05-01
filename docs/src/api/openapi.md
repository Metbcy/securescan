# OpenAPI specification

The full SecureScan REST API is auto-generated as an OpenAPI 3.1 document at runtime. Two ways to consume it:

## Live spec (running backend)

```bash
curl http://localhost:8000/api/v1/openapi.json | jq .
```

The spec is regenerated on every backend startup, so it always matches the running version.

## Interactive docs

```
http://localhost:8000/docs       # Swagger UI
http://localhost:8000/redoc      # ReDoc alternative
```

Both surfaces are protected by the same auth as the rest of the API. In dev mode (no `SECURESCAN_API_KEY`, no DB keys) they're accessible without credentials.

## Importing into tooling

### Postman
File → Import → paste the URL `http://localhost:8000/api/v1/openapi.json`. Postman auto-creates a collection from the spec.

### Insomnia
Application → Preferences → Data → Import Data → From URL → paste the URL.

### Backstage
Use the [openapi entity definition](https://backstage.io/docs/features/software-catalog/descriptor-format#kind-api):

```yaml
apiVersion: backstage.io/v1alpha1
kind: API
metadata:
  name: securescan
spec:
  type: openapi
  definition: |
    \${{ jsonData '/api/v1/openapi.json' }}
```

## Endpoint count

As of v0.11.0, the auto-generated spec covers ~30 endpoints across:
- `/api/v1/scans/*` — scan lifecycle + SSE events + delete
- `/api/v1/findings/*` — triage state + comments
- `/api/v1/sbom/*` — SBOM generation + retrieval
- `/api/v1/dashboard/*` — scanner status + stats
- `/api/v1/keys/*` — API key CRUD (admin)
- `/api/v1/webhooks/*` — webhook CRUD (admin)
- `/api/v1/notifications/*` — in-app notifications
- `/health`, `/ready` — liveness/readiness probes
- `/openapi.json`, `/docs`, `/redoc` — meta
