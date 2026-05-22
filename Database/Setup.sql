-- =============================================
-- Dynamic API Database Setup Script
-- =============================================

-- Create database (run this first, then switch to the database)
-- CREATE DATABASE DynamicApi;
-- GO
-- USE DynamicApi;
-- GO

-- =============================================
-- Drop existing objects (for clean setup)
-- =============================================
IF OBJECT_ID('ApiEndpointConfig', 'U') IS NOT NULL
    DROP TABLE ApiEndpointConfig;
GO

IF OBJECT_ID('usp_GetCustomerById', 'P') IS NOT NULL
    DROP PROCEDURE usp_GetCustomerById;
GO

IF OBJECT_ID('usp_CreateOrder', 'P') IS NOT NULL
    DROP PROCEDURE usp_CreateOrder;
GO

IF OBJECT_ID('usp_DeleteProduct', 'P') IS NOT NULL
    DROP PROCEDURE usp_DeleteProduct;
GO

IF OBJECT_ID('usp_GetAllCustomers', 'P') IS NOT NULL
    DROP PROCEDURE usp_GetAllCustomers;
GO

IF OBJECT_ID('usp_UpdateCustomer', 'P') IS NOT NULL
    DROP PROCEDURE usp_UpdateCustomer;
GO

IF OBJECT_ID('Customers', 'U') IS NOT NULL
    DROP TABLE Customers;
GO

IF OBJECT_ID('Orders', 'U') IS NOT NULL
    DROP TABLE Orders;
GO

IF OBJECT_ID('Products', 'U') IS NOT NULL
    DROP TABLE Products;
GO

IF OBJECT_ID('RefreshTokens', 'U') IS NOT NULL
    DROP TABLE RefreshTokens;
GO

IF OBJECT_ID('Users', 'U') IS NOT NULL
    DROP TABLE Users;
GO

-- =============================================
-- Create Authentication Tables
-- =============================================

CREATE TABLE Users (
    Id INT IDENTITY(1,1) PRIMARY KEY,
    Username NVARCHAR(100) NOT NULL UNIQUE,
    PasswordHash NVARCHAR(500) NOT NULL,
    Email NVARCHAR(200) NOT NULL,
    Role NVARCHAR(50) DEFAULT 'User',
    CreatedAt DATETIME2 DEFAULT DATEADD(MINUTE, 330, GETUTCDATE()),
    IsActive BIT DEFAULT 1
);
GO

CREATE INDEX IX_Users_Username ON Users(Username);
CREATE INDEX IX_Users_Email ON Users(Email);
GO

CREATE TABLE RefreshTokens (
    Id INT IDENTITY(1,1) PRIMARY KEY,
    Token NVARCHAR(500) NOT NULL UNIQUE,
    Username NVARCHAR(100) NOT NULL,
    ExpiresAt DATETIME2 NOT NULL,
    CreatedAt DATETIME2 DEFAULT DATEADD(MINUTE, 330, GETUTCDATE()),
    IsRevoked BIT DEFAULT 0,
    RevokedAt DATETIME2 NULL,
    CONSTRAINT FK_RefreshTokens_Users FOREIGN KEY (Username) REFERENCES Users(Username)
);
GO

CREATE INDEX IX_RefreshTokens_Token ON RefreshTokens(Token);
CREATE INDEX IX_RefreshTokens_Username ON RefreshTokens(Username);
GO

-- Seed default admin user (password: admin123)
INSERT INTO Users (Username, PasswordHash, Email, Role, IsActive)
VALUES ('admin', 'wTmfNTFjS/7b8HR4dK+YLK1kBrT-jArN7lEiI9Gky8Y=', 'admin@dyapi.com', 'Admin', 1);
GO

-- =============================================
-- Create Sample Tables
-- =============================================

CREATE TABLE Customers (
    CustomerId INT IDENTITY(1,1) PRIMARY KEY,
    FirstName NVARCHAR(100) NOT NULL,
    LastName NVARCHAR(100) NOT NULL,
    Email NVARCHAR(200) NOT NULL,
    Phone NVARCHAR(50),
    CreatedAt DATETIME2 DEFAULT DATEADD(MINUTE, 330, GETUTCDATE())
);
GO

CREATE TABLE Products (
    ProductId INT IDENTITY(1,1) PRIMARY KEY,
    ProductName NVARCHAR(200) NOT NULL,
    Description NVARCHAR(500),
    Price DECIMAL(18,2) NOT NULL,
    StockQuantity INT DEFAULT 0,
    IsActive BIT DEFAULT 1
);
GO

CREATE TABLE Orders (
    OrderId INT IDENTITY(1,1) PRIMARY KEY,
    CustomerId INT NOT NULL,
    OrderDate DATETIME2 DEFAULT DATEADD(MINUTE, 330, GETUTCDATE()),
    TotalAmount DECIMAL(18,2) NOT NULL,
    Status NVARCHAR(50) DEFAULT 'Pending',
    FOREIGN KEY (CustomerId) REFERENCES Customers(CustomerId)
);
GO

-- =============================================
-- Create API Endpoint Configuration Table
-- =============================================

CREATE TABLE ApiEndpointConfig (
    Id INT IDENTITY(1,1) PRIMARY KEY,
    MethodName NVARCHAR(100) NOT NULL,
    HttpVerb NVARCHAR(10) NOT NULL,
    RouteTemplate NVARCHAR(200) NOT NULL,
    StoredProcedureName NVARCHAR(200) NOT NULL,
    ParameterNames NVARCHAR(MAX) NULL,
    IsActive BIT NOT NULL DEFAULT 1,
    Description NVARCHAR(500) NULL,
    RequiredRole NVARCHAR(100) NULL,
    ApplicationID INT NULL,
    APICall NVARCHAR(50) DEFAULT 'Normal', -- Normal, SMS, etc.
    CreatedAt DATETIME2 DEFAULT DATEADD(MINUTE, 330, GETUTCDATE()),
    UpdatedAt DATETIME2 NULL
);
GO

-- =============================================
-- Create Sample Stored Procedures
-- =============================================

-- Stored Procedure 1: Get Customer by ID
CREATE PROCEDURE usp_GetCustomerById
    @customerId INT
AS
BEGIN
    SET NOCOUNT ON;
    
    SELECT 
        CustomerId,
        FirstName,
        LastName,
        Email,
        Phone,
        CreatedAt
    FROM Customers
    WHERE CustomerId = @customerId;
END
GO

-- Stored Procedure 2: Get All Customers
CREATE PROCEDURE usp_GetAllCustomers
AS
BEGIN
    SET NOCOUNT ON;
    
    SELECT 
        CustomerId,
        FirstName,
        LastName,
        Email,
        Phone,
        CreatedAt
    FROM Customers
    ORDER BY CreatedAt DESC;
END
GO

-- Stored Procedure 3: Create Order
CREATE PROCEDURE usp_CreateOrder
    @customerId INT,
    @totalAmount DECIMAL(18,2),
    @status NVARCHAR(50) = 'Pending'
AS
BEGIN
    SET NOCOUNT ON;
    
    INSERT INTO Orders (CustomerId, TotalAmount, Status)
    VALUES (@customerId, @totalAmount, @status);
    
    SELECT CAST(SCOPE_IDENTITY() AS INT) AS OrderId;
END
GO

-- Stored Procedure 4: Delete Product
CREATE PROCEDURE usp_DeleteProduct
    @productId INT
AS
BEGIN
    SET NOCOUNT ON;
    
    IF EXISTS (SELECT 1 FROM Products WHERE ProductId = @productId)
    BEGIN
        UPDATE Products SET IsActive = 0 WHERE ProductId = @productId;
        SELECT 1 AS Success, 'Product deleted successfully' AS Message;
    END
    ELSE
    BEGIN
        SELECT 0 AS Success, 'Product not found' AS Message;
    END
END
GO

-- Stored Procedure 5: Update Customer
CREATE PROCEDURE usp_UpdateCustomer
    @customerId INT,
    @firstName NVARCHAR(100) = NULL,
    @lastName NVARCHAR(100) = NULL,
    @email NVARCHAR(200) = NULL,
    @phone NVARCHAR(50) = NULL
AS
BEGIN
    SET NOCOUNT ON;
    
    IF NOT EXISTS (SELECT 1 FROM Customers WHERE CustomerId = @customerId)
    BEGIN
        SELECT 0 AS Success, 'Customer not found' AS Message;
        RETURN;
    END
    
    UPDATE Customers SET
        FirstName = COALESCE(@firstName, FirstName),
        LastName = COALESCE(@lastName, LastName),
        Email = COALESCE(@email, Email),
        Phone = COALESCE(@phone, Phone),
        UpdatedAt = DATEADD(MINUTE, 330, GETUTCDATE())
    WHERE CustomerId = @customerId;
    
    SELECT 1 AS Success, 'Customer updated successfully' AS Message;
END
GO

-- =============================================
-- Seed API Endpoint Configuration
-- =============================================

-- GET endpoint: Get customer by ID
INSERT INTO ApiEndpointConfig (MethodName, HttpVerb, RouteTemplate, StoredProcedureName, ParameterNames, IsActive, Description)
VALUES ('GetCustomerById', 'GET', 'api/customers/{customerId}', 'usp_GetCustomerById', 'customerId', 1, 'Retrieves a customer by their unique identifier');

-- GET endpoint: Get all customers
INSERT INTO ApiEndpointConfig (MethodName, HttpVerb, RouteTemplate, StoredProcedureName, ParameterNames, IsActive, Description)
VALUES ('GetAllCustomers', 'GET', 'api/customers', 'usp_GetAllCustomers', '', 1, 'Retrieves all customers');

-- POST endpoint: Create order
INSERT INTO ApiEndpointConfig (MethodName, HttpVerb, RouteTemplate, StoredProcedureName, ParameterNames, IsActive, Description)
VALUES ('CreateOrder', 'POST', 'api/orders', 'usp_CreateOrder', 'customerId,totalAmount,status', 1, 'Creates a new order for a customer');

-- DELETE endpoint: Delete product
INSERT INTO ApiEndpointConfig (MethodName, HttpVerb, RouteTemplate, StoredProcedureName, ParameterNames, IsActive, Description)
VALUES ('DeleteProduct', 'DELETE', 'api/products/{productId}', 'usp_DeleteProduct', 'productId', 1, 'Soft deletes a product by setting IsActive to 0');

-- PUT endpoint: Update customer
INSERT INTO ApiEndpointConfig (MethodName, HttpVerb, RouteTemplate, StoredProcedureName, ParameterNames, IsActive, Description)
VALUES ('UpdateCustomer', 'PUT', 'api/customers/{customerId}', 'usp_UpdateCustomer', 'customerId,firstName,lastName,email,phone', 1, 'Updates customer information');

GO

-- =============================================
-- Seed Sample Data
-- =============================================

-- Insert sample customers
INSERT INTO Customers (FirstName, LastName, Email, Phone)
VALUES 
    ('John', 'Doe', 'john.doe@example.com', '555-0101'),
    ('Jane', 'Smith', 'jane.smith@example.com', '555-0102'),
    ('Bob', 'Johnson', 'bob.johnson@example.com', '555-0103'),
    ('Alice', 'Williams', 'alice.williams@example.com', '555-0104'),
    ('Charlie', 'Brown', 'charlie.brown@example.com', '555-0105');
GO

-- Insert sample products
INSERT INTO Products (ProductName, Description, Price, StockQuantity)
VALUES 
    ('Laptop', 'High-performance laptop', 999.99, 50),
    ('Mouse', 'Wireless optical mouse', 29.99, 200),
    ('Keyboard', 'Mechanical gaming keyboard', 89.99, 100),
    ('Monitor', '27-inch 4K display', 449.99, 30),
    ('Headphones', 'Noise-cancelling headphones', 199.99, 75);
GO

-- Insert sample orders
INSERT INTO Orders (CustomerId, TotalAmount, Status)
VALUES 
    (1, 1029.98, 'Completed'),
    (2, 89.99, 'Pending'),
    (3, 649.98, 'Processing'),
    (1, 199.99, 'Completed'),
    (4, 449.99, 'Pending');
GO

-- =============================================
-- Verify Setup
-- =============================================

SELECT 'ApiEndpointConfig rows:' AS Info;
SELECT * FROM ApiEndpointConfig;
GO

SELECT 'Sample Customers:' AS Info;
SELECT * FROM Customers;
GO

SELECT 'Sample Products:' AS Info;
SELECT * FROM Products;
GO

SELECT 'Sample Orders:' AS Info;
SELECT * FROM Orders;
GO
