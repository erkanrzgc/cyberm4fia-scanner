# TLS fixture certificates

Generated once at test bring-up time. **Not committed.** The
`make integration-up` target runs:

```bash
openssl req -x509 -nodes -newkey rsa:2048 \
  -keyout key.pem -out cert.pem -days 3650 \
  -subj "/CN=weak-tls-fixture.test"
```

…and writes the resulting `cert.pem` + `key.pem` into this directory before
`docker compose up` mounts them into the `weak-tls` service.

Throwaway, fixture-only. Do not reuse anywhere real.
