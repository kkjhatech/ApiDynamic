-- =============================================
-- JWT Authentication Stored Procedures
-- =============================================

-- Drop existing procedures
IF OBJECT_ID('usp_SaveRefreshToken', 'P') IS NOT NULL
    DROP PROCEDURE usp_SaveRefreshToken;
GO

IF OBJECT_ID('usp_GetRefreshToken', 'P') IS NOT NULL
    DROP PROCEDURE usp_GetRefreshToken;
GO

IF OBJECT_ID('usp_GetUserByUsername', 'P') IS NOT NULL
    DROP PROCEDURE usp_GetUserByUsername;
GO

IF OBJECT_ID('usp_RevokeRefreshToken', 'P') IS NOT NULL
    DROP PROCEDURE usp_RevokeRefreshToken;
GO

-- =============================================
-- Procedure: Save Refresh Token
-- =============================================
CREATE PROCEDURE usp_SaveRefreshToken
    @Token NVARCHAR(500),
    @Username NVARCHAR(100),
    @ExpiresAt DATETIME2,
    @CreatedAt DATETIME2 = NULL
AS
BEGIN
    SET NOCOUNT ON;

    IF @CreatedAt IS NULL
        SET @CreatedAt = DATEADD(MINUTE, 330, GETUTCDATE());

    INSERT INTO RefreshTokens (Token, Username, ExpiresAt, CreatedAt, IsRevoked)
    VALUES (@Token, @Username, @ExpiresAt, @CreatedAt, 0);

    SELECT CAST(SCOPE_IDENTITY() AS INT) AS TokenId;
END
GO

-- =============================================
-- Procedure: Get Refresh Token
-- =============================================
CREATE PROCEDURE usp_GetRefreshToken
    @Token NVARCHAR(500)
AS
BEGIN
    SET NOCOUNT ON;

    SELECT
        Id,
        Token,
        Username,
        ExpiresAt,
        CreatedAt,
        IsRevoked,
        RevokedAt
    FROM RefreshTokens
    WHERE Token = @Token;
END
GO

-- =============================================
-- Procedure: Get User by Username
-- =============================================
CREATE PROCEDURE usp_GetUserByUsername
    @Username NVARCHAR(100)
AS
BEGIN
    SET NOCOUNT ON;

    SELECT
        Id,
        Username,
        PasswordHash,
        Email,
        Role,
        CreatedAt,
        IsActive
    FROM Users
    WHERE Username = @Username AND IsActive = 1;
END
GO

-- =============================================
-- Procedure: Revoke Refresh Token
-- =============================================
CREATE PROCEDURE usp_RevokeRefreshToken
    @Token NVARCHAR(500)
AS
BEGIN
    SET NOCOUNT ON;

    UPDATE RefreshTokens
    SET IsRevoked = 1, RevokedAt = DATEADD(MINUTE, 330, GETUTCDATE())
    WHERE Token = @Token;

    SELECT @@ROWCOUNT AS RowsAffected;
END
GO

-- =============================================
-- Verify Procedures
-- =============================================
SELECT 'JWT Procedures created successfully' AS Message;
GO