# OIDC 2.1 SSO Backend

Enterprise-grade OpenID Connect 2.1 Authorization Server built with Rust, compliant with OWASP ASVS Level 3, NIST 800-63B, ISO 27001, and GDPR.

## Features

- ✅ **OAuth 2.1 Compliant**: Authorization code flow with mandatory PKCE
- ✅ **OpenID Connect**: Full OIDC provider capabilities
- 🔒 **Security Hardened**: OWASP ASVS Level 3 controls
- 🔐 **Strong Authentication**: NIST 800-63B AAL2/AAL3 support with MFA
- 📊 **Audit Logging**: ISO 27001 compliant audit trails
- 🇪🇺 **GDPR Compliant**: Data subject rights implementation
- ⚡ **High Performance**: Async Rust with tokio runtime
- 🗄️ **PostgreSQL**: Relational database with ACID guarantees
- 🚀 **Redis**: High-performance session storage

## Architecture

```
├── crates/
│   ├── auth-server/       # Main authorization server
│   ├── authentication/    # Password & MFA handling
│   ├── security/          # JWT, PKCE, cryptography
│   ├── audit/            # Audit logging
│   ├── federation/       # External IdP integration
│   ├── clients/          # OAuth client management
│   └── users/            # User account management
├── migrations/           # Database migrations
└── docs/                # Documentation
```

## Quick Start

### Prerequisites

- Rust 1.75+ (`rustup install stable`)
- PostgreSQL 14+
- Redis 7+

### Setup

1. Clone the repository:
```bash
git clone https://github.com/your-org/rust-oidc-sso.git
cd rust-oidc-sso
```

2. Copy environment configuration:
```bash
cp .env.example .env
```

3. Configure database and Redis in `.env`:
```env
DATABASE_URL=postgresql://user:password@localhost:5432/oidc_db
REDIS_URL=redis://localhost:6379
```

4. Generate JWT signing keys:
```bash
mkdir -p keys
openssl genrsa -out keys/private_key.pem 4096
openssl rsa -in keys/private_key.pem -pubout -out keys/public_key.pem
```

5. Run migrations:
```bash
cargo install sqlx-cli
sqlx database create
sqlx migrate run
```

6. Start the server:
```bash
cargo run -p auth-server
```

Server will start on `http://localhost:8080`

## Endpoints

### OAuth 2.1 / OIDC Endpoints

- `GET /.well-known/openid-configuration` - Discovery document
- `GET /authorize` - Authorization endpoint
- `POST /token` - Token endpoint
- `GET /userinfo` - UserInfo endpoint
- `GET /jwks` - JSON Web Key Set
- `POST /revoke` - Token revocation
- `POST /introspect` - Token introspection

### Operational

- `GET /health` - Health check

## Security Compliance

### OWASP ASVS Level 3
- ✅ Password hashing with Argon2id (m=64MB, t=3, p=4)
- ✅ Minimum 12 character passwords
- ✅ HaveIBeenPwned breach detection
- ✅ Rate limiting (5 attempts per 15 minutes)
- ✅ Secure session management
- ✅ CSRF protection via state parameter
- ✅ Input validation and sanitization

### NIST 800-63B
- ✅ AAL2 session timeouts (15min idle, 12hr absolute)
- ✅ MFA support (TOTP, WebAuthn)
- ✅ No composition rules on passwords
- ✅ No periodic password rotation
- ✅ Account lockout after failed attempts

### ISO 27001:2022
- ✅ Access control (A.8.3)
- ✅ Cryptography (A.8.24)
- ✅ Audit logging (A.12 .4)
- ✅ Privileged access management (A.8.2)

### GDPR
- ✅ Consent management
- ✅ Data subject rights (export, deletion)
- ✅ Audit trails
- ✅ Data retention policies

## Development

### Build

```bash
cargo build
```

### Test

```bash
cargo test --workspace
```

### Lint

```bash
cargo clippy --all-targets --all-features
```

### Format

```bash
cargo fmt --all
```

## Configuration

See `.env.example` for all available configuration options.

Key settings:
- Session timeouts (NIST 800-63B compliance)
- Password policy
- Rate limiting
- MFA requirements
- GDPR data retention

## Documentation

- [Implementation Plan](../brain/implementation_plan.md)
- [Security Requirements](../brain/security_requirements.md)
- [OAuth 2.1 Specification](../brain/oauth21_spec_reference.md)

## License

MIT OR Apache-2.0

## Contributing

Contributions welcome! Please ensure all code:
- Passes `cargo clippy`
- Includes tests
- Follows security best practices
- Updates documentation

## Security

For security issues, please email security@example.com instead of using the issue tracker.
