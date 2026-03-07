# Test Certificates

The `.pem` and `.key` files in this directory are **self-signed test certificates**
generated for unit testing only. They are NOT real certificates and are safe to
include in a public repository.

| File | Subject | Issuer | Expires |
|------|---------|--------|---------|
| `server.pem` | CN=localhost | TLS Test CA | 2030 |
| `server.key` | ECDSA P-256 private key for server.pem | — | — |
| `wronghost.pem` | CN=wronghost.com | TLS Test CA | 2030 |
| `wronghost.key` | ECDSA P-256 private key for wronghost.pem | — | — |

These certificates are used by `test_socket.mojo` and `test_connection.mojo`
to test TLS handshake and hostname verification logic against a local test server.
