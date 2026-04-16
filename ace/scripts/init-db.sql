-- ACE Platform — PostgreSQL database initialization
-- Runs automatically on first container start via docker-entrypoint-initdb.d

CREATE DATABASE ace_mitre;
CREATE DATABASE ace_assets;

GRANT ALL PRIVILEGES ON DATABASE ace_mitre TO ace;
GRANT ALL PRIVILEGES ON DATABASE ace_assets TO ace;
