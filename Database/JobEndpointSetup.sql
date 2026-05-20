-- ====================================================
-- Setup for Job endpoint with nested customFiels object
-- ====================================================

USE DynamicApi;
GO

-- 1. Core Jobs table (stores only the non‑nested fields)
CREATE TABLE Jobs (
    Id INT IDENTITY(1,1) PRIMARY KEY,
    JobId NVARCHAR(50) NOT NULL,
    Country NVARCHAR(10) NOT NULL,
    Language NVARCHAR(50) NULL,
    CreatedAt DATETIME DEFAULT GETDATE()
);
GO

-- 2. Dynamic key‑value table for any custom fields supplied in the JSON payload
CREATE TABLE JobCustomFields (
    Id INT IDENTITY(1,1) PRIMARY KEY,
    JobId INT NOT NULL,
    FieldName NVARCHAR(100) NOT NULL,
    FieldValue NVARCHAR(MAX) NULL,
    CONSTRAINT FK_JobCustomFields_Jobs FOREIGN KEY (JobId) REFERENCES Jobs(Id) ON DELETE CASCADE
);
GO

-- 3. Stored procedure that receives the customFiels object as JSON
--    and stores each custom field as a separate row in JobCustomFields.
CREATE PROCEDURE sp_CreateJob
    @jobid       NVARCHAR(50),
    @country     NVARCHAR(10),
    @customFiels NVARCHAR(MAX),   -- whole JSON object containing arbitrary custom fields
    @languate    NVARCHAR(50)
AS
BEGIN
    SET NOCOUNT ON;

    -- Insert the core job record
    INSERT INTO Jobs (JobId, Country, Language)
    VALUES (@jobid, @country, @languate);

    DECLARE @NewJobId INT = SCOPE_IDENTITY();

    -- Insert each key/value pair from the JSON object into the dynamic table
    INSERT INTO JobCustomFields (JobId, FieldName, FieldValue)
    SELECT @NewJobId, [key], [value]
    FROM OPENJSON(@customFiels);

    SELECT @NewJobId AS NewJobId;
END;
GO

-- 4. Register the endpoint configuration (dot‑notation list uses the whole JSON object as a single parameter)
INSERT INTO ApiEndpointConfig (
    MethodName, HttpVerb, RouteTemplate, StoredProcedureName,
    ParameterNames, Description, RequiredRole, APICall
) VALUES (
    'CreateJob',
    'POST',
    'api/jobs',
    'sp_CreateJob',
    'jobid,country,customFiels,languate',
    'Create a job record; customFiels JSON stored dynamically as key‑value rows.',
    'User',
    'Normal'
);
GO

PRINT 'Job endpoint setup completed successfully.';
