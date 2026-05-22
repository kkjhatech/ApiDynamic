-- =============================================
-- Auth Service Stored Procedures
-- =============================================

-- Drop existing procedures
IF OBJECT_ID('usp_RegisterUser', 'P') IS NOT NULL
    DROP PROCEDURE usp_RegisterUser;
GO

IF OBJECT_ID('usp_ValidateCredentials', 'P') IS NOT NULL
    DROP PROCEDURE usp_ValidateCredentials;
GO

IF OBJECT_ID('usp_GetUserByUsername', 'P') IS NOT NULL
    DROP PROCEDURE usp_GetUserByUsername;
GO

IF OBJECT_ID('usp_UserExists', 'P') IS NOT NULL
    DROP PROCEDURE usp_UserExists;
GO

-- =============================================
-- Procedure: Register User
-- =============================================
CREATE PROCEDURE usp_RegisterUser
    @Username NVARCHAR(100),
    @PasswordHash NVARCHAR(500),
    @Email NVARCHAR(200),
    @Role NVARCHAR(50) = 'User'
AS
BEGIN
    SET NOCOUNT ON;

    INSERT INTO Users (Username, PasswordHash, Email, Role, CreatedAt, IsActive)
    VALUES (@Username, @PasswordHash, @Email, @Role, DATEADD(MINUTE, 330, GETUTCDATE()), 1);

    SELECT CAST(SCOPE_IDENTITY() AS INT) AS UserId;
END
GO

-- =============================================
-- Procedure: Validate Credentials
-- =============================================
CREATE PROCEDURE usp_ValidateCredentials
    @Username NVARCHAR(100)
AS
BEGIN
    SET NOCOUNT ON;

    SELECT PasswordHash
    FROM Users
    WHERE Username = @Username AND IsActive = 1;
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

    SELECT Id, Username, PasswordHash, Email, Role, CreatedAt, IsActive
    FROM Users
    WHERE Username = @Username AND IsActive = 1;
END
GO

-- =============================================
-- Procedure: Check if User Exists
-- =============================================
CREATE PROCEDURE usp_UserExists
    @Username NVARCHAR(100)
AS
BEGIN
    SET NOCOUNT ON;

    SELECT COUNT(1) AS UserCount
    FROM Users
    WHERE Username = @Username;
END
GO

-- =============================================
-- Endpoint Config Stored Procedures
-- =============================================

-- Drop existing procedures
IF OBJECT_ID('usp_GetAllActiveEndpoints', 'P') IS NOT NULL
    DROP PROCEDURE usp_GetAllActiveEndpoints;
GO

-- =============================================
-- Procedure: Get All Active Endpoints
-- =============================================
CREATE PROCEDURE usp_GetAllActiveEndpoints
AS
BEGIN
    SET NOCOUNT ON;

    SELECT Id, MethodName, HttpVerb, RouteTemplate, StoredProcedureName,
           ParameterNames, IsActive, Description, RequiredRole
    FROM ApiEndpointConfig
    WHERE IsActive = 1;
END
GO

-- =============================================
-- Verify Procedures
-- =============================================
SELECT 'Auth and Endpoint Config procedures created successfully' AS Message;
GO