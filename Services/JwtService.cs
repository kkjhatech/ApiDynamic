using Dapper;
using DyApi.Models;
using Microsoft.IdentityModel.Tokens;
using System.Data.SqlClient;
using System.IdentityModel.Tokens.Jwt;
using System.Security.Claims;
using System.Security.Cryptography;
using System.Text;

namespace DyApi.Services;

public class JwtService : IJwtService
{
    private readonly JwtSettings _jwtSettings;
    private readonly string _connectionString;
    private readonly ILogger<JwtService> _logger;

    public JwtService(IConfiguration configuration, ILogger<JwtService> logger)
    {
        _jwtSettings = configuration.GetSection("Jwt").Get<JwtSettings>() 
            ?? throw new InvalidOperationException("JWT settings not found in configuration.");
        _connectionString = configuration.GetConnectionString("DefaultConnection") 
            ?? throw new InvalidOperationException("DefaultConnection not found.");
        _logger = logger;
    }

    public LoginResponse GenerateTokens(User user)
    {
        var accessToken = GenerateAccessToken(user);
        var refreshToken = GenerateRefreshToken();

        SaveRefreshToken(user.Username, refreshToken);

        return new LoginResponse
        {
            AccessToken = accessToken,
            RefreshToken = refreshToken,
            TokenType = "Bearer",
            ExpiresIn = _jwtSettings.AccessTokenExpiryMinutes * 60,
            ExpiresAt = DateTime.UtcNow.AddMinutes(_jwtSettings.AccessTokenExpiryMinutes)
        };
    }

    public async Task<LoginResponse?> RefreshTokensAsync(string refreshToken)
    {
        var storedToken = await GetRefreshTokenAsync(refreshToken);
        
        if (storedToken == null || !storedToken.IsActive)
        {
            _logger.LogWarning("Invalid or expired refresh token used");
            return null;
        }

        var user = await GetUserByUsernameAsync(storedToken.Username);
        if (user == null || !user.IsActive)
        {
            _logger.LogWarning("User not found or inactive for refresh token");
            return null;
        }

        await RevokeRefreshTokenAsync(refreshToken);
        
        return GenerateTokens(user);
    }

    public async Task<bool> RevokeRefreshTokenAsync(string refreshToken)
    {
        const string sql = @"
            UPDATE RefreshTokens 
            SET IsRevoked = 1, RevokedAt = GETUTCDATE() 
            WHERE Token = @Token";

        using var connection = new SqlConnection(_connectionString);
        var rowsAffected = await connection.ExecuteAsync(sql, new { Token = refreshToken });
        
        if (rowsAffected > 0)
        {
            _logger.LogInformation("Refresh token revoked successfully");
            return true;
        }
        
        return false;
    }

    public string? ValidateAccessToken(string token)
    {
        try
        {
            var tokenHandler = new JwtSecurityTokenHandler();
            var key = Encoding.UTF8.GetBytes(_jwtSettings.SecretKey);

            tokenHandler.ValidateToken(token, new TokenValidationParameters
            {
                ValidateIssuerSigningKey = true,
                IssuerSigningKey = new SymmetricSecurityKey(key),
                ValidateIssuer = true,
                ValidIssuer = _jwtSettings.Issuer,
                ValidateAudience = true,
                ValidAudience = _jwtSettings.Audience,
                ValidateLifetime = true,
                ClockSkew = TimeSpan.Zero
            }, out SecurityToken validatedToken);

            var jwtToken = (JwtSecurityToken)validatedToken;
            var username = jwtToken.Claims.First(x => x.Type == ClaimTypes.Name).Value;
            
            return username;
        }
        catch (Exception ex)
        {
            _logger.LogWarning("Token validation failed: {Message}", ex.Message);
            return null;
        }
    }

    public async Task<bool> IsRefreshTokenValidAsync(string refreshToken)
    {
        var token = await GetRefreshTokenAsync(refreshToken);
        return token?.IsActive == true;
    }

    private string GenerateAccessToken(User user)
    {
        var key = Encoding.UTF8.GetBytes(_jwtSettings.SecretKey);
        var credentials = new SigningCredentials(
            new SymmetricSecurityKey(key), 
            SecurityAlgorithms.HmacSha256);

        var claims = new[]
        {
            new Claim(ClaimTypes.Name, user.Username),
            new Claim(ClaimTypes.Email, user.Email),
            new Claim(ClaimTypes.Role, user.Role),
            new Claim("userId", user.Id.ToString()),
            new Claim(JwtRegisteredClaimNames.Jti, Guid.NewGuid().ToString())
        };

        var token = new JwtSecurityToken(
            issuer: _jwtSettings.Issuer,
            audience: _jwtSettings.Audience,
            claims: claims,
            expires: DateTime.UtcNow.AddMinutes(_jwtSettings.AccessTokenExpiryMinutes),
            signingCredentials: credentials
        );

        return new JwtSecurityTokenHandler().WriteToken(token);
    }

    private static string GenerateRefreshToken()
    {
        var randomBytes = new byte[64];
        using var rng = RandomNumberGenerator.Create();
        rng.GetBytes(randomBytes);
        return Convert.ToBase64String(randomBytes);
    }

    private void SaveRefreshToken(string username, string token)
    {
        const string sql = @"
            INSERT INTO RefreshTokens (Token, Username, ExpiresAt, CreatedAt, IsRevoked)
            VALUES (@Token, @Username, @ExpiresAt, @CreatedAt, 0)";

        using var connection = new SqlConnection(_connectionString);
        connection.Execute(sql, new
        {
            Token = token,
            Username = username,
            ExpiresAt = DateTime.UtcNow.AddDays(_jwtSettings.RefreshTokenExpiryDays),
            CreatedAt = DateTime.UtcNow
        });
    }

    private async Task<RefreshToken?> GetRefreshTokenAsync(string token)
    {
        const string sql = @"
            SELECT Id, Token, Username, ExpiresAt, CreatedAt, IsRevoked, RevokedAt
            FROM RefreshTokens 
            WHERE Token = @Token";

        using var connection = new SqlConnection(_connectionString);
        return await connection.QueryFirstOrDefaultAsync<RefreshToken>(sql, new { Token = token });
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
}
