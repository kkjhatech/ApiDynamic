-- =============================================
-- Authentication Tables Setup Script
-- =============================================

-- Create Users table
IF OBJECT_ID('Users', 'U') IS NULL
BEGIN
    CREATE TABLE Users (
        Id INT IDENTITY(1,1) PRIMARY KEY,
        Username NVARCHAR(100) NOT NULL UNIQUE,
        PasswordHash NVARCHAR(500) NOT NULL,
        Email NVARCHAR(200) NOT NULL,
        Role NVARCHAR(50) DEFAULT 'User',
        CreatedAt DATETIME2 DEFAULT GETUTCDATE(),
        IsActive BIT DEFAULT 1
    );
    
    CREATE INDEX IX_Users_Username ON Users(Username);
    CREATE INDEX IX_Users_Email ON Users(Email);
END
GO

-- Create RefreshTokens table
IF OBJECT_ID('RefreshTokens', 'U') IS NULL
BEGIN
    CREATE TABLE RefreshTokens (
        Id INT IDENTITY(1,1) PRIMARY KEY,
        Token NVARCHAR(500) NOT NULL UNIQUE,
        Username NVARCHAR(100) NOT NULL,
        ExpiresAt DATETIME2 NOT NULL,
        CreatedAt DATETIME2 DEFAULT GETUTCDATE(),
        IsRevoked BIT DEFAULT 0,
        RevokedAt DATETIME2 NULL,
        CONSTRAINT FK_RefreshTokens_Users FOREIGN KEY (Username) REFERENCES Users(Username)
    );
    
    CREATE INDEX IX_RefreshTokens_Token ON RefreshTokens(Token);
    CREATE INDEX IX_RefreshTokens_Username ON RefreshTokens(Username);
    CREATE INDEX IX_RefreshTokens_ExpiresAt ON RefreshTokens(ExpiresAt);
END
GO

-- Create stored procedure for cleaning up expired refresh tokens
IF OBJECT_ID('usp_CleanupExpiredRefreshTokens', 'P') IS NOT NULL
    DROP PROCEDURE usp_CleanupExpiredRefreshTokens;
GO

CREATE PROCEDURE usp_CleanupExpiredRefreshTokens
AS
BEGIN
    SET NOCOUNT ON;
    
    DELETE FROM RefreshTokens 
    WHERE ExpiresAt < DATEADD(DAY, -30, GETUTCDATE()) 
       OR (IsRevoked = 1 AND RevokedAt < DATEADD(DAY, -7, GETUTCDATE()));
    
    SELECT @@ROWCOUNT AS DeletedCount;
END
GO

-- Seed default admin user (password: admin123)
IF NOT EXISTS (SELECT 1 FROM Users WHERE Username = 'admin')
BEGIN
    INSERT INTO Users (Username, PasswordHash, Email, Role, IsActive)
    VALUES ('admin', 'wTmfNTFjS/7b8HR4dK+YLK1kBrT-jArN7lEiI9Gky8Y=', 'admin@dyapi.com', 'Admin', 1);
END
GO

-- Seed test user (password: test123)
IF NOT EXISTS (SELECT 1 FROM Users WHERE Username = 'testuser')
BEGIN
    INSERT INTO Users (Username, PasswordHash, Email, Role, IsActive)
    VALUES ('testuser', '6paO6j7y1D7AYMNh3D/7b8HR4dK+YLK1kBrT-jArN7lEiI9Gky8Y=', 'test@dyapi.com', 'User', 1);
END
GO

-- Verify setup
SELECT 'Users table:' AS Info;
SELECT * FROM Users;

SELECT 'RefreshTokens table (should be empty):' AS Info;
SELECT COUNT(*) AS TokenCount FROM RefreshTokens;
GO
