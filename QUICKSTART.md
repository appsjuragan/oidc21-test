# Quick Start Guide

Complete setup guide for running the OIDC 2.1 SSO Backend locally.

## Prerequisites

- **Rust**: 1.75 or later (`curl --proto '=https' --tlsv1.2 -sSf https://sh.rustup.rs | sh`)
- **Docker**: For PostgreSQL and Redis
- **OpenSSL**: For generating JWT keys

## 1. Start Infrastructure

```bash
# Start PostgreSQL and Redis
docker-compose up -d

# Verify containers are running
docker-compose ps
```

## 2. Generate  JWT Keys

```bash
# Create keys directory
mkdir -p keys

# Generate RSA 4096-bit private key
openssl genrsa -out keys/private_key.pem 4096

# Extract public key
openssl rsa -in keys/private_key.pem -pubout -out keys/public_key.pem

# Verify keys
ls -lh keys/
```

## 3. Configure Environment

```bash
# Copy example configuration
cp .env.example .env

# Edit .env if needed (defaults should work)
# DATABASE_URL=postgresql://oidc_user:secure_password@localhost:5432/oidc_db
# REDIS_URL=redis://localhost:6379
```

## 4. Run Database Migrations

```bash
# Install sqlx-cli
cargo install sqlx-cli --no-default-features --features postgres

# Create database
sqlx database create

# Run migrations
sqlx migrate run

# Verify tables
sqlx migrate info
```

## 5. Build and Run

```bash
# Build all crates
cargo build --release

# Run the server
cargo run -p auth-server --release

# In development (with faster compile times)
cargo run -p auth-server
```

Server will start on `http://localhost:8080`

## 6. Test Endpoints

### Health Check
```bash
curl http://localhost:8080/health
```

Expected response:
```json
{
  "status": "healthy",
  "database": "ok",
  "redis": "ok"
}
```

### Discovery Document
```bash
curl http://localhost:8080/.well-known/openid-configuration | jq
```

### JWKS (Public Keys)
```bash
curl http://localhost:8080/jwks | jq
```

## 7. Create Test Data

### Create Test Client

```sql
-- Connect to database
psql postgresql://oidc_user:secure_password@localhost:5432/oidc_db

-- Insert test client
INSERT INTO clients (
    client_id,
    client_name,
    client_type,
    redirect_uris,
    grant_types,
    allowed_scopes
) VALUES (
    'test_client',
    'Test Application',
    'public',
    ARRAY['http://localhost:3000/callback'],
    ARRAY['authorization_code', 'refresh_token'],
    ARRAY['openid', 'profile', 'email']
);
```

### Create Test User

```rust
// Use authentication crate to hash password
use authentication::hash_password;

let password_hash = hash_password("MySecurePassword123!").unwrap();
println!("Hash: {}", password_hash);
```

```sql
-- Insert test user with hashed password
INSERT INTO users (
    email,
    password_hash,
    email_verified,
    name,
    is_active
) VALUES (
    'test@example.com',
    '$argon2id$v=19$m=65536,t=3,p=4$...', -- paste hash from above
    true,
    'Test User',
    true
);
```

## 8. Test Login Flow

```bash
# Login request
curl -X POST http://localhost:8080/auth/login \
  -H "Content-Type: application/json" \
  -d '{
    "email": "test@example.com",
    "password": "MySecurePassword123!"
  }'
```

Expected response:
```json
{
  "session_token": "abc123...",
  "user_id": "uuid...",
  "requires_mfa": false
}
```

## 9. Test OAuth Flow (Manual)

1. **Authorization Request** (open in browser):
```
http://localhost:8080/authorize?
  response_type=code
  &client_id=test_client
  &redirect_uri=http://localhost:3000/callback
  &scope=openid%20profile%20email
  &state=random_state_123
  &code_challenge=CHALLENGE_HERE
  &code_challenge_method=S256
```

2. **Generate PKCE Verifier** (use security crate):
```rust
use security::{generate_code_verifier, create_code_challenge};

let verifier = generate_code_verifier();
let challenge = create_code_challenge(&verifier).unwrap();
println!("Verifier: {}", verifier);
println!("Challenge: {}", challenge);
```

3. **Token Exchange**:
```bash
curl -X POST http://localhost:8080/token \
  -H "Content-Type: application/x-www-form-urlencoded" \
  -d "grant_type=authorization_code" \
  -d "code=AUTH_CODE_FROM_REDIRECT" \
  -d "redirect_uri=http://localhost:3000/callback" \
  -d "client_id=test_client" \
  -d "code_verifier=VERIFIER_FROM_STEP_2"
```

## 10. Development Tips

### Hot Reload
```bash
# Install cargo-watch
cargo install cargo-watch

# Run with auto-reload
cargo watch -x 'run -p auth-server'
```

### Database Inspection
```bash
# Connect to PostgreSQL
docker exec -it oidc-postgres psql -U oidc_user -d oidc_db

# View tables
\dt

# View users
SELECT id, email, name, is_active FROM users;

# View clients
SELECT client_id, client_name, client_type FROM clients;
```

### Redis Inspection
```bash
# Connect to Redis
docker exec -it oidc-redis redis-cli

# View all keys
KEYS *

# View session
GET session:TOKEN_HERE

# View user sessions
SMEMBERS user_sessions:USER_ID_HERE
```

### Logs
```bash
# Set debug logging
export RUST_LOG=debug,auth_server=trace

# Run with detailed logs
cargo run -p auth-server
```

## Troubleshooting

### Database Connection Failed
```bash
# Check PostgreSQL is running
docker-compose ps postgres

# Check connection
psql $DATABASE_URL -c "SELECT 1"
```

### Redis Connection Failed
```bash
# Check Redis is running
docker exec -it oidc-redis redis-cli ping

# Should respond: PONG
```

### JWT Key Errors
```bash
# Verify key permissions
ls -l keys/

# Keys should be readable
chmod 600 keys/private_key.pem
chmod 644 keys/public_key.pem
```

### Build Errors
```bash
# Clean and rebuild
cargo clean
cargo build

# Update dependencies
cargo update
```

## Next Steps

- Add MFA: Enroll TOTP for test user
- Create more clients with different grant types
- Test token refresh flow
- Implement rate limiting
- Add admin API endpoints

## Production Deployment

For production deployment:
1. Use managed PostgreSQL (AWS RDS, Google Cloud SQL)
2. Use managed Redis (AWS ElastiCache, Redis Cloud)
3. Store JWT keys in HSM or AWS KMS
4. Enable TLS with valid certificates
5. Configure proper CORS origins
6. Set up monitoring (Prometheus, Grafana)
7. Configure backup strategy
8. Review security settings in `.env`
