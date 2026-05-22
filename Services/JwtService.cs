using Dapper;
using DyApi.Models;
using Microsoft.IdentityModel.Tokens;
using System.Data;
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
        var now = DateTime.UtcNow.AddHours(5.5);
        var accessToken = GenerateAccessToken(user, now);
        var refreshToken = GenerateRefreshToken();

        SaveRefreshToken(user.Username, refreshToken, now);

        return new LoginResponse
        {
            AccessToken = accessToken,
            RefreshToken = refreshToken,
            TokenType = "Bearer",
            ExpiresIn = _jwtSettings.AccessTokenExpiryMinutes * 60,
            ExpiresAt = now.AddMinutes(_jwtSettings.AccessTokenExpiryMinutes)
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
        using var connection = new SqlConnection(_connectionString);

        var rowsAffected = await connection.QueryFirstOrDefaultAsync<int>(
            "usp_RevokeRefreshToken", new { Token = refreshToken }, commandType: CommandType.StoredProcedure);
        
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

    private string GenerateAccessToken(User user, DateTime now)
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
            expires: now.AddMinutes(_jwtSettings.AccessTokenExpiryMinutes),
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

    private void SaveRefreshToken(string username, string token, DateTime now)
    {
        using var connection = new SqlConnection(_connectionString);
        connection.Execute("usp_SaveRefreshToken", new
        {
            Token = token,
            Username = username,
            ExpiresAt = now.AddDays(_jwtSettings.RefreshTokenExpiryDays),
            CreatedAt = now
        }, commandType: CommandType.StoredProcedure);
    }

    private async Task<RefreshToken?> GetRefreshTokenAsync(string token)
    {
        using var connection = new SqlConnection(_connectionString);
        return await connection.QueryFirstOrDefaultAsync<RefreshToken>(
            "usp_GetRefreshToken", new { Token = token }, commandType: CommandType.StoredProcedure);
    }

    private async Task<User?> GetUserByUsernameAsync(string username)
    {
        using var connection = new SqlConnection(_connectionString);
        return await connection.QueryFirstOrDefaultAsync<User>(
            "usp_GetUserByUsername", new { Username = username }, commandType: CommandType.StoredProcedure);
    }
}
