-- Initial database schema for OIDC 2.1 SSO Backend
-- Compliant with OWASP ASVS, NIST 800-63B, ISO 27001, and GDPR

-- Enable UUID extension
CREATE EXTENSION IF NOT EXISTS "uuid-ossp";

-- Users table (ISO 27001 A.5.16 - Identity Management)
CREATE TABLE users (
    id UUID PRIMARY KEY DEFAULT uuid_generate_v4(),
    email VARCHAR(255) UNIQUE NOT NULL,
    email_verified BOOLEAN DEFAULT FALSE,
    -- Argon2id hash (OWASP ASVS 2.4.1)
    password_hash VARCHAR(255) NOT NULL,
    
    -- User profile (OIDC standard claims)
    name VARCHAR(255),
    phone_number VARCHAR(50),
    phone_number_verified BOOLEAN DEFAULT FALSE,
    picture_url VARCHAR(500),
    
    -- Account status
    is_active BOOLEAN DEFAULT TRUE,
    is_admin BOOLEAN DEFAULT FALSE,
    
    -- Failed login tracking (OWASP ASVS 2.2.1)
    failed_login_attempts INTEGER DEFAULT 0,
    locked_until TIMESTAMP,
    
    -- Timestamps
    created_at TIMESTAMP NOT NULL DEFAULT NOW(),
    updated_at TIMESTAMP NOT NULL DEFAULT NOW(),
    last_login_at TIMESTAMP,
    password_changed_at TIMESTAMP DEFAULT NOW()
);

-- Index for email lookup
CREATE INDEX idx_users_email ON users(email);
CREATE INDEX idx_users_locked_until ON users(locked_until) WHERE locked_until IS NOT NULL;

-- OAuth/OIDC Clients table
CREATE TABLE clients (
    id UUID PRIMARY KEY DEFAULT uuid_generate_v4(),
    client_id VARCHAR(255) UNIQUE NOT NULL,
    client_secret_hash VARCHAR(255), -- NULL for public clients
    client_name VARCHAR(255) NOT NULL,
    
    -- Client type: "confidential" or "public"
    client_type VARCHAR(20) NOT NULL,
    
    -- Registered redirect URIs (exact match required)
    redirect_uris TEXT[] NOT NULL,
    
    -- Allowed grant types
    grant_types TEXT[] NOT NULL DEFAULT ARRAY['authorization_code'],
    
    -- Allowed scopes
    allowed_scopes TEXT[] NOT NULL DEFAULT ARRAY['openid', 'profile', 'email'],
    
    -- Status
    is_active BOOLEAN DEFAULT TRUE,
    
    -- Timestamps
    created_at TIMESTAMP NOT NULL DEFAULT NOW(),
    updated_at TIMESTAMP NOT NULL DEFAULT NOW()
);

CREATE INDEX idx_clients_client_id ON clients(client_id);

-- Authorization codes (short-lived, OAuth 2.1 Section 4.1)
CREATE TABLE authorization_codes (
    id UUID PRIMARY KEY DEFAULT uuid_generate_v4(),
    code VARCHAR(255) UNIQUE NOT NULL,
    client_id UUID NOT NULL REFERENCES clients(id) ON DELETE CASCADE,
    user_id UUID NOT NULL REFERENCES users(id) ON DELETE CASCADE,
    
    -- PKCE (OAuth 2.1 mandatory)
    code_challenge VARCHAR(255) NOT NULL,
    code_challenge_method VARCHAR(10) NOT NULL DEFAULT 'S256',
    
    -- Authorization details
    redirect_uri TEXT NOT NULL,
    scope TEXT,
    nonce VARCHAR(255), -- OIDC nonce for replay prevention
    
    -- Expiration (max 10 minutes recommended)
    expires_at TIMESTAMP NOT NULL,
    used_at TIMESTAMP,
    
    created_at TIMESTAMP NOT NULL DEFAULT NOW()
);

CREATE INDEX idx_authz_codes_code ON authorization_codes(code);
CREATE INDEX idx_authz_codes_expires_at ON authorization_codes(expires_at);

-- Access tokens (for revocation tracking)
CREATE TABLE access_tokens (
    id UUID PRIMARY KEY DEFAULT uuid_generate_v4(),
    token_hash VARCHAR(255) UNIQUE NOT NULL, -- SHA256 hash of JWT
    client_id UUID NOT NULL REFERENCES clients(id) ON DELETE CASCADE,
    user_id UUID REFERENCES users(id) ON DELETE CASCADE, -- NULL for client_credentials
    
    scope TEXT,
    expires_at TIMESTAMP NOT NULL,
    revoked_at TIMESTAMP,
    
    created_at TIMESTAMP NOT NULL DEFAULT NOW()
);

CREATE INDEX idx_access_tokens_hash ON access_tokens(token_hash);
CREATE INDEX idx_access_tokens_expires_at ON access_tokens(expires_at);

-- Refresh tokens with rotation tracking
CREATE TABLE refresh_tokens (
    id UUID PRIMARY KEY DEFAULT uuid_generate_v4(),
    token_hash VARCHAR(255) UNIQUE NOT NULL,
    client_id UUID NOT NULL REFERENCES clients(id) ON DELETE CASCADE,
    user_id UUID NOT NULL REFERENCES users(id) ON DELETE CASCADE,
    
    scope TEXT,
    
    -- Rotation tracking (security best practice)
    parent_token_id UUID REFERENCES refresh_tokens(id),
    
    expires_at TIMESTAMP NOT NULL,
    used_at TIMESTAMP,
    revoked_at TIMESTAMP,
    
    created_at TIMESTAMP NOT NULL DEFAULT NOW()
);

CREATE INDEX idx_refresh_tokens_hash ON refresh_tokens(token_hash);
CREATE INDEX idx_refresh_tokens_user_id ON refresh_tokens(user_id);

-- User sessions (NIST 800-63B AAL2)
CREATE TABLE sessions (
    id UUID PRIMARY KEY DEFAULT uuid_generate_v4(),
    session_token VARCHAR(255) UNIQUE NOT NULL,
    user_id UUID NOT NULL REFERENCES users(id) ON DELETE CASCADE,
    
    -- Device information for anomaly detection
    user_agent TEXT,
    ip_address INET,
    device_fingerprint VARCHAR(255),
    
    -- Session timeouts (NIST 800-63B)
    last_activity_at TIMESTAMP NOT NULL DEFAULT NOW(),
    expires_at TIMESTAMP NOT NULL,
    
    created_at TIMESTAMP NOT NULL DEFAULT NOW()
);

CREATE INDEX idx_sessions_token ON sessions(session_token);
CREATE INDEX idx_sessions_user_id ON sessions(user_id);
CREATE INDEX idx_sessions_expires_at ON sessions(expires_at);

-- Audit logs (ISO 27001 A.12.4, GDPR Article 30)
CREATE TABLE audit_logs (
    id UUID PRIMARY KEY DEFAULT uuid_generate_v4(),
    
    -- Event classification
    event_type VARCHAR(50) NOT NULL, -- 'login', 'token_issued', 'data_export', etc.
    event_category VARCHAR(50) NOT NULL, -- 'authentication', 'authorization', 'data_access'
    
    -- Who
    user_id UUID REFERENCES users(id) ON DELETE SET NULL,
    client_id UUID REFERENCES clients(id) ON DELETE SET NULL,
    
    -- What
    resource VARCHAR(255),
    action VARCHAR(50),
    outcome VARCHAR(20) NOT NULL, -- 'success', 'failure'
    
    -- Where
    ip_address INET,
    user_agent TEXT,
    
    -- Details (JSON for flexibility)
    details JSONB,
    
    -- When (immutable timestamp)
    created_at TIMESTAMP NOT NULL DEFAULT NOW()
);

CREATE INDEX idx_audit_logs_event_type ON audit_logs(event_type);
CREATE INDEX idx_audit_logs_user_id ON audit_logs(user_id);
CREATE INDEX idx_audit_logs_created_at ON audit_logs(created_at DESC);

-- User consents (GDPR Article 7)
CREATE TABLE consents (
    id UUID PRIMARY KEY DEFAULT uuid_generate_v4(),
    user_id UUID NOT NULL REFERENCES users(id) ON DELETE CASCADE,
    client_id UUID NOT NULL REFERENCES clients(id) ON DELETE CASCADE,
    
    -- Granted scopes
    scopes TEXT[] NOT NULL,
    
    -- Consent metadata
    granted_at TIMESTAMP NOT NULL DEFAULT NOW(),
    withdrawn_at TIMESTAMP,
    
    -- Processing purposes (GDPR Article 13)
    purposes TEXT[],
    
    UNIQUE(user_id, client_id)
);

CREATE INDEX idx_consents_user_id ON consents(user_id);

-- MFA credentials (NIST 800-63B AAL2)
CREATE TABLE mfa_credentials (
    id UUID PRIMARY KEY DEFAULT uuid_generate_v4(),
    user_id UUID NOT NULL REFERENCES users(id) ON DELETE CASCADE,
    
    -- MFA type: 'totp', 'webauthn', 'sms'
    mfa_type VARCHAR(20) NOT NULL,
    
    -- TOTP secret (encrypted)
    totp_secret VARCHAR(255),
    
    -- WebAuthn credential data (JSON)
    webauthn_credential JSONB,
    
    -- Backup codes
    backup_codes TEXT[],
    
    -- Status
    is_active BOOLEAN DEFAULT TRUE,
    verified_at TIMESTAMP,
    
    created_at TIMESTAMP NOT NULL DEFAULT NOW()
);

CREATE INDEX idx_mfa_user_id ON mfa_credentials(user_id);

-- Update timestamp trigger function
CREATE OR REPLACE FUNCTION update_updated_at_column()
RETURNS TRIGGER AS $$
BEGIN
    NEW.updated_at = NOW();
    RETURN NEW;
END;
$$ language 'plpgsql';

-- Apply update trigger to tables with updated_at
CREATE TRIGGER update_users_updated_at BEFORE UPDATE ON users
    FOR EACH ROW EXECUTE FUNCTION update_updated_at_column();

CREATE TRIGGER update_clients_updated_at BEFORE UPDATE ON clients
    FOR EACH ROW EXECUTE FUNCTION update_updated_at_column();
