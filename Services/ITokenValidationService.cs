using System.Security.Claims;

namespace DyApi.Services;

public interface ITokenValidationService
{
    /// <summary>
    /// Validates a Bearer token and returns the username if valid
    /// </summary>
    /// <param name="token">The Bearer token to validate</param>
    /// <returns>Username if token is valid, null otherwise</returns>
    string? ValidateAccessToken(string token);

    /// <summary>
    /// Validates a Bearer token and returns all claims if valid
    /// </summary>
    /// <param name="token">The Bearer token to validate</param>
    /// <returns>ClaimsPrincipal if token is valid, null otherwise</returns>
    ClaimsPrincipal? ValidateTokenAndGetClaims(string token);

    /// <summary>
    /// Gets the authentication scheme name (JWT, OAuth, etc.)
    /// </summary>
    string AuthenticationScheme { get; }
}
