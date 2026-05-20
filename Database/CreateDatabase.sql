-- =============================================
-- Create Database Script (run this first)
-- =============================================

USE master;
GO

-- Check if database exists and drop if needed
IF EXISTS (SELECT name FROM sys.databases WHERE name = 'DynamicApi')
BEGIN
    ALTER DATABASE DynamicApi SET SINGLE_USER WITH ROLLBACK IMMEDIATE;
    DROP DATABASE DynamicApi;
END
GO

-- Create the database
CREATE DATABASE DynamicApi;
GO

USE DynamicApi;
GO

PRINT 'Database DynamicApi created successfully.';
GO
