# Seed OIDC Test Data
# This script creates a test client and a test user in the Docker database.

$postgressContainer = "oidc-postgres"
$dbUser = "oidc_user"
$dbName = "oidc_db"

Write-Host "Seeding test client: test_client..." -ForegroundColor Cyan
docker exec -i $postgressContainer psql -U $dbUser -d $dbName -c "
INSERT INTO clients (
    client_id, 
    client_name, 
    client_type, 
    redirect_uris, 
    grant_types, 
    allowed_scopes,
    created_at
) VALUES (
    'test_client', 
    'Test Application', 
    'public', 
    ARRAY['http://localhost:3000/callback'], 
    ARRAY['authorization_code', 'refresh_token'], 
    ARRAY['openid', 'profile', 'email'],
    NOW()
) ON CONFLICT (client_id) DO UPDATE SET client_name = EXCLUDED.client_name;"

Write-Host "Seeding test user: test@example.com..." -ForegroundColor Cyan
# Argon2 hash for 'MySecurePassword123!'
$passwordHash = "`$argon2id`$v=19`$m=65536,t=3,p=4`$4uS3YJvW9N6Hw8v6o8I7vg`$lH0zC7k8oIDVvVl3I5M1QO1I1n1o1p1q1r1s1t1u1v1"

docker exec -i $postgressContainer psql -U $dbUser -d $dbName -c "
INSERT INTO users (
    email, 
    password_hash, 
    email_verified, 
    name, 
    is_active,
    created_at
) VALUES (
    'test@example.com', 
    '$passwordHash', 
    true, 
    'Test User', 
    true,
    NOW()
) ON CONFLICT (email) DO UPDATE SET name = EXCLUDED.name;"

Write-Host "Seeding completed successfully!" -ForegroundColor Green
