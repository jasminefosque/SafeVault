-- SafeVault Database Schema
-- This SQL script creates the Users table with proper security considerations

-- Create Users table
CREATE TABLE IF NOT EXISTS Users (
    Id INTEGER PRIMARY KEY AUTOINCREMENT,
    Username TEXT NOT NULL UNIQUE,
    Email TEXT NOT NULL UNIQUE,
    PasswordHash TEXT NOT NULL,
    Role TEXT NOT NULL DEFAULT 'user',
    CreatedAt DATETIME DEFAULT CURRENT_TIMESTAMP,
    UpdatedAt DATETIME DEFAULT CURRENT_TIMESTAMP
);

-- Create index on Username for faster lookups
CREATE INDEX IF NOT EXISTS idx_users_username ON Users(Username);

-- Create index on Email for faster lookups
CREATE INDEX IF NOT EXISTS idx_users_email ON Users(Email);

-- Insert sample admin user (password: SecureAdmin123!)
-- Note: In production, passwords should be hashed using the AuthService.HashPassword method
INSERT OR IGNORE INTO Users (Id, Username, Email, PasswordHash, Role) 
VALUES (1, 'admin', 'admin@safevault.com', 
        '$2a$11$N9qo8uLOickgx2ZMRZoMyeIjZAgcfl7p92ldGxad68LJZdL17lhWy', 
        'admin');

-- Insert sample regular user (password: SecureUser123!)
INSERT OR IGNORE INTO Users (Id, Username, Email, PasswordHash, Role) 
VALUES (2, 'john_doe', 'john@example.com', 
        '$2a$11$8K1p/a0dL3LpsVOY5NvOeeZR1fhSVBcF0RwF8c8pD5iQ7cz3sRlX.', 
        'user');

-- Security Notes:
-- 1. PasswordHash column stores BCrypt hashed passwords (never plain text)
-- 2. All queries in UserRepository use parameterized queries to prevent SQL injection
-- 3. Input validation is performed before any database operations
-- 4. UNIQUE constraints prevent duplicate usernames and emails
-- 5. Role-based access control is enforced at the application level

-- Example of INSECURE query (DO NOT USE):
-- SELECT * FROM Users WHERE Username = '" + username + "'";
-- This is vulnerable to SQL injection!

-- Example of SECURE query (ALWAYS USE):
-- Using parameterized queries:
-- SELECT * FROM Users WHERE Username = @Username

-- Common SQL Injection Attack Examples (for testing):
-- Input: admin' OR '1'='1
-- Input: '; DROP TABLE Users; --
-- Input: admin'--
-- These should be blocked by InputSanitizer.ContainsSqlInjectionPattern()
-- and prevented by parameterized queries in UserRepository
