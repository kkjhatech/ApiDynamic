using System.Security.Claims;

namespace DyApi.Interfaces;

public interface ITokenValidationService
{
    string? ValidateAccessToken(string token);
    ClaimsPrincipal? ValidateTokenAndGetClaims(string token);
    string AuthenticationScheme { get; }
}
