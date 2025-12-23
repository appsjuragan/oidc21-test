# Postman API Testing

Complete Postman collection for testing all OIDC 2.1 endpoints with automated test scripts and PKCE generation.

## Quick Start

### 1. Import Collection

1. Open Postman
2. Click **Import**
3. Select `postman/OIDC-SSO-Backend.postman_collection.json`
4. Select `postman/OIDC-SSO-Local.postman_environment.json`

### 2. Select Environment

- Click environment dropdown (top right)
- Select **"OIDC SSO - Local Development"**

### 3. Configure Variables

Update these environment variables:

| Variable | Default | Description |
|----------|---------|-------------|
| `base_url` | `http://localhost:8080` | Server URL |
| `user_email` | `test@example.com` | Test user email |
| `user_password` | `MySecurePassword123!` | Test user password |
| `client_id` | `test_client` | OAuth client ID |
| `redirect_uri` | `http://localhost:3000/callback` | OAuth redirect |

**Note:** `access_token`, `refresh_token`, `session_token`, and PKCE values are auto-populated by test scripts.

## Testing Flows

### Flow 1: Health Check & Discovery

1. **Health Check** - Verify server is running
2. **OpenID Configuration** - Get server capabilities
3. **JWKS** - Get public keys for token verification

**Expected:** All return 200 OK with valid JSON

### Flow 2: Simple Login

1. **Login (Password Only)** - Authenticate user
2. **Logout** - Terminate session

**Auto-populates:** `session_token`

**Test Scripts Validate:**
- ✅ 200 OK response
- ✅ Session token is returned
- ✅ User ID is provided

### Flow 3: Login with MFA

1. **Login (Password Only)** - Returns `requires_mfa: true`
2. Set `mfa_code` environment variable with 6-digit TOTP code
3. **Login (with MFA)** - Completes authentication

**Prerequisites:** User must have MFA enrolled

### Flow 4: Complete OAuth 2.1 Authorization Code Flow

#### Step 1: Generate PKCE
Run **"Step 1: Generate PKCE"** request

**What it does:**
- Generates cryptographically secure `code_verifier` (43-128 chars)
- Computes SHA-256 hash to create `code_challenge`
- Auto-saves to environment variables
- Generates random `state` for CSRF protection

**Check Console:** Pre-request script logs PKCE values

#### Step 2: Authorization Request
Run **"Step 2: Authorization Request"**

**What happens:**
- Redirects to login if not authenticated
- After login, shows consent screen (if needed)
- Redirects to `redirect_uri` with authorization code

**IMPORTANT:** Postman will show redirect warning. This is expected!

**Manual Step Required:**
1. Look at the redirect URL (it will fail since `http://localhost:3000` doesn't exist)
2. Copy the `code` parameter from URL
3. Set `auth_code` environment variable with this value

Example redirect:
```
http://localhost:3000/callback?code=ABC123XYZ&state=random_state
```
Set `auth_code` = `ABC123XYZ`

#### Step 3: Token Exchange
Run **"Step 3: Token Exchange"**

**What it does:**
- Exchanges authorization code for tokens
- Verifies PKCE challenge
- Returns access token and refresh token

**Auto-populates:** `access_token` and `refresh_token`

**Test Scripts Validate:**
- ✅ Access token is JWT
- ✅ Refresh token provided
- ✅ Token type is "Bearer"
- ✅ Expires_in is present

### Flow 5: Token Operations

#### Refresh Token
Run **"Refresh Token"**

**What it does:**
- Uses current refresh token to get new access token
- Rotates refresh token (old one is invalidated)
- Updates environment with new tokens

**Test Scripts:**
- ✅ New access token differs from old
- ✅ New refresh token differs from old (rotation)

#### Client Credentials
Run **"Client Credentials Grant"**

**Prerequisites:**
- Client must be confidential type
- Set `client_secret` in environment

**What it does:**
- Machine-to-machine authentication
- No refresh token (as per OAuth 2.1 spec)

#### Token Introspection
Run **"Token Introspection"**

**Prerequisites:**
- Set `client_credentials_base64` = Base64(`client_id`:`client_secret`)

**What it does:**
- Checks if token is active
- Returns token metadata

#### Token Revocation
Run **"Token Revocation"**

**What it does:**
- Invalidates access or refresh token
- Always returns 200 OK (even if token invalid)

### Flow 6: UserInfo

Run **"Get UserInfo"**

**Prerequisites:** Valid `access_token` in environment

**What it does:**
- Returns user claims based on token scopes
- Implements GDPR data minimization
- Only returns claims for granted scopes

**Example Response:**
```json
{
  "sub": "user-uuid",
  "name": "Test User",
  "email": "test@example.com",
  "email_verified": true
}
```

**Scopes determine claims:**
- `profile` scope → name, picture
- `email` scope → email, email_verified
- `phone` scope → phone_number, phone_number_verified

## Test Automation

### Running Collection with Newman

```bash
# Install Newman
npm install -g newman

# Run entire collection
newman run postman/OIDC-SSO-Backend.postman_collection.json \
  --environment postman/OIDC-SSO-Local.postman_environment.json

# Run with detailed output
newman run postman/OIDC-SSO-Backend.postman_collection.json \
  --environment postman/OIDC-SSO-Local.postman_environment.json \
  --reporters cli,json \
  --reporter-json-export results.json
```

### Collection Runner

1. Click **Collections** sidebar
2. Right-click **"OIDC 2.1 SSO Backend"**
3. Select **Run collection**
4. Configure:
   - Iterations: 1
   - Delay: 500ms between requests
   - Environment: OIDC SSO - Local Development
5. Click **Run**

**View Results:**
- Pass/Fail for each test
- Response times
- Test assertions

## Test Scripts Explained

### Pre-request Scripts

**PKCE Generation (Step 1):**
```javascript
// Generates cryptographically secure random verifier
const verifier = generateCodeVerifier();

// Creates SHA-256 challenge
const challenge = await generateCodeChallenge(verifier);

// Saves to environment
pm.environment.set('code_verifier', verifier);
pm.environment.set('code_challenge', challenge);
```

### Post-response Scripts

**Auto-save Tokens:**
```javascript
// Extract tokens from response
var jsonData = pm.response.json();

// Save for subsequent requests
pm.environment.set('access_token', jsonData.access_token);
pm.environment.set('refresh_token', jsonData.refresh_token);
```

**Validate Response:**
```javascript
pm.test('Status code is 200', function () {
    pm.response.to.have.status(200);
});

pm.test('Has required fields', function () {
    var jsonData = pm.response.json();
    pm.expect(jsonData).to.have.property('access_token');
});
```

## Common Issues

### 1. "code_challenge required" Error

**Cause:** PKCE values not generated

**Solution:** Run "Step 1: Generate PKCE" before authorization request

### 2. "Invalid authorization code" Error

**Cause:** 
- Code already used (single-use)
- Code expired (10-minute lifetime)
- Wrong `code_verifier`

**Solution:** Generate new code by repeating OAuth flow from Step 1

### 3. "Invalid redirect_uri" Error

**Cause:** redirect_uri doesn't exactly match registered URI

**Solution:** Ensure `redirect_uri` environment variable matches client configuration

### 4. 401 Unauthorized on UserInfo

**Cause:** 
- Access token expired (15-minute lifetime)
- Token not in environment

**Solution:** Get new access token (refresh or re-authenticate)

### 5. Session Token Empty After Login

**Cause:** MFA required but not provided

**Solution:** 
- Check response: `requires_mfa: true`
- Set `mfa_code` variable
- Use "Login (with MFA)" request

## Advanced Usage

### Testing Token Expiration

1. Get access token
2. Wait 16 minutes (default expiration)
3. Call UserInfo - should get 401
4. Refresh token - should succeed
5. Call UserInfo with new token - should succeed

### Testing Account Lockout

1. Login with wrong password 5 times
2. 6th attempt should return "Account locked"
3. Wait 15 minutes (default lockout duration)
4. Login should succeed

### Testing PKCE Validation

1. Generate PKCE values
2. Modify `code_verifier` in environment
3. Try token exchange
4. Should fail with "PKCE verification failed"

### Testing Scope Limitations

1. Request tokens with `scope=email`
2. Call UserInfo
3. Response should only have `sub` and `email` fields
4. Should NOT have `name` (requires `profile` scope)

## CI/CD Integration

### GitHub Actions Example

```yaml
name: API Tests

on: [push, pull_request]

jobs:
  test:
    runs-on: ubuntu-latest
    steps:
      - uses: actions/checkout@v2
      
      - name: Start services
        run: docker-compose up -d
      
      - name: Wait for services
        run: sleep 10
      
      - name: Run migrations
        run: sqlx migrate run
      
      - name: Start auth server
        run: cargo run -p auth-server &
        
      - name: Wait for server
        run: sleep 5
      
      - name: Install Newman
        run: npm install -g newman
      
      - name: Run Postman tests
        run: |
          newman run postman/OIDC-SSO-Backend.postman_collection.json \
            --environment postman/OIDC-SSO-Local.postman_environment.json \
            --reporters cli,junit \
            --reporter-junit-export results.xml
      
      - name: Publish test results
        uses: EnricoMi/publish-unit-test-result-action@v2
        if: always()
        with:
          files: results.xml
```

## Variables Reference

| Variable | Type | Auto-populated | Description |
|----------|------|----------------|-------------|
| `base_url` | string | No | API base URL |
| `user_email` | string | No | Test user email |
| `user_password` | secret | No | Test user password |
| `client_id` | string | No | OAuth client ID |
| `client_secret` | secret | No | OAuth client secret |
| `redirect_uri` | string | No | OAuth redirect URI |
| `session_token` | string | Yes | Session after login |
| `access_token` | secret | Yes | JWT access token |
| `refresh_token` | secret | Yes | Refresh token |
| `code_verifier` | string | Yes | PKCE verifier |
| `code_challenge` | string | Yes | PKCE challenge |
| `oauth_state` | string | Yes | CSRF state parameter |
| `auth_code` | string | **MANUAL** | Authorization code from redirect |
| `mfa_code` | string | No | 6-digit TOTP code |

## Next Steps

1. Create test data (user, client) following QUICKSTART.md
2. Run health checks to verify server
3. Test login flow
4. Test complete OAuth flow
5. Automate with Newman in CI/CD
