using DyApi.Models;

namespace DyApi.Services;

public interface IJwtService
{
    LoginResponse GenerateTokens(User user);
    Task<LoginResponse?> RefreshTokensAsync(string refreshToken);
    Task<bool> RevokeRefreshTokenAsync(string refreshToken);
    string? ValidateAccessToken(string token);
    Task<bool> IsRefreshTokenValidAsync(string refreshToken);
}
