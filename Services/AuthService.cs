using Dapper;
using DyApi.Models;
using System.Data.SqlClient;
using System.Security.Cryptography;
using System.Text;

namespace DyApi.Services;

public class AuthService : IAuthService
{
    private readonly string _connectionString;
    private readonly IJwtService _jwtService;
    private readonly ILogger<AuthService> _logger;

    public AuthService(IConfiguration configuration, IJwtService jwtService, ILogger<AuthService> logger)
    {
        _connectionString = configuration.GetConnectionString("DefaultConnection") 
            ?? throw new InvalidOperationException("DefaultConnection not found.");
        _jwtService = jwtService;
        _logger = logger;
    }

    public async Task<LoginResponse?> LoginAsync(LoginRequest request)
    {
        if (!await ValidateCredentialsAsync(request.Username, request.Password))
        {
            _logger.LogWarning("Failed login attempt for user: {Username}", request.Username);
            return null;
        }

        var user = await GetUserByUsernameAsync(request.Username);
        if (user == null)
        {
            return null;
        }

        _logger.LogInformation("User {Username} logged in successfully", request.Username);
        return _jwtService.GenerateTokens(user);
    }

    public async Task<bool> LogoutAsync(string refreshToken)
    {
        return await _jwtService.RevokeRefreshTokenAsync(refreshToken);
    }

    public async Task<bool> RegisterAsync(User user, string password)
    {
        if (await UserExistsAsync(user.Username))
        {
            _logger.LogWarning("Registration failed: Username {Username} already exists", user.Username);
            return false;
        }

        var passwordHash = HashPassword(password);

        const string sql = @"
            INSERT INTO Users (Username, PasswordHash, Email, Role, CreatedAt, IsActive)
            VALUES (@Username, @PasswordHash, @Email, @Role, GETUTCDATE(), 1)";

        using var connection = new SqlConnection(_connectionString);
        var rowsAffected = await connection.ExecuteAsync(sql, new
        {
            user.Username,
            PasswordHash = passwordHash,
            user.Email,
            user.Role
        });

        if (rowsAffected > 0)
        {
            _logger.LogInformation("User {Username} registered successfully", user.Username);
            return true;
        }

        return false;
    }

    public async Task<bool> ValidateCredentialsAsync(string username, string password)
    {
        const string sql = "SELECT PasswordHash FROM Users WHERE Username = @Username AND IsActive = 1";

        using var connection = new SqlConnection(_connectionString);
        var passwordHash = await connection.QueryFirstOrDefaultAsync<string>(sql, new { Username = username });

        if (passwordHash == null)
        {
            return false;
        }

        return VerifyPassword(password, passwordHash);
    }

    private async Task<User?> GetUserByUsernameAsync(string username)
    {
        const string sql = @"
            SELECT Id, Username, PasswordHash, Email, Role, CreatedAt, IsActive
            FROM Users 
            WHERE Username = @Username AND IsActive = 1";

        using var connection = new SqlConnection(_connectionString);
        return await connection.QueryFirstOrDefaultAsync<User>(sql, new { Username = username });
    }

    private async Task<bool> UserExistsAsync(string username)
    {
        const string sql = "SELECT COUNT(1) FROM Users WHERE Username = @Username";
        
        using var connection = new SqlConnection(_connectionString);
        var count = await connection.ExecuteScalarAsync<int>(sql, new { Username = username });
        return count > 0;
    }

    private static string HashPassword(string password)
    {
        using var sha256 = SHA256.Create();
        var bytes = sha256.ComputeHash(Encoding.UTF8.GetBytes(password));
        return Convert.ToBase64String(bytes);
    }

    private static bool VerifyPassword(string password, string passwordHash)
    {
        var hash = HashPassword(password);
        return hash == passwordHash;
    }
}
