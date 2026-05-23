using DyApi.Interfaces;
using System.Security.Claims;
using Microsoft.IdentityModel.Tokens;
using Microsoft.IdentityModel.Protocols.OpenIdConnect;
using Microsoft.IdentityModel.Protocols;
using System.IdentityModel.Tokens.Jwt;
using System.Threading;
using DyApi.Models;
using System.Net.Http.Headers;
using System.Text.Json;

namespace DyApi.Services;

/// <summary>
/// OAuth 2.0 / OpenID Connect token validation service
/// Supports JWT tokens and opaque tokens (via introspection)
/// </summary>
public class OAuthTokenValidationService : ITokenValidationService
{
    private readonly OAuthSettings _settings;
    private readonly ILogger<OAuthTokenValidationService> _logger;
    private readonly IConfigurationManager<OpenIdConnectConfiguration> _configManager;
    private readonly HttpClient _httpClient;

    public string AuthenticationScheme => "OAuth 2.0";

    public OAuthTokenValidationService(IConfiguration configuration, ILogger<OAuthTokenValidationService> logger)
    {
        _settings = configuration.GetSection("OAuth").Get<OAuthSettings>()
            ?? throw new InvalidOperationException("OAuth settings not found in configuration.");
        _logger = logger;
        _httpClient = new HttpClient();

        if (string.IsNullOrEmpty(_settings.Authority))
        {
            throw new InvalidOperationException("OAuth:Authority is required.");
        }

        var metadataAddress = $"{_settings.Authority.TrimEnd('/')}/.well-known/openid-configuration";
        _configManager = new ConfigurationManager<OpenIdConnectConfiguration>(
            metadataAddress,
            new OpenIdConnectConfigurationRetriever(),
            new HttpDocumentRetriever()
            {
                RequireHttps = _settings.RequireHttpsMetadata
            });

        _logger.LogInformation("OAuth 2.0 validation configured for provider: {Provider}, Authority: {Authority}",
            _settings.Provider, _settings.Authority);
    }

    public string? ValidateAccessToken(string token)
    {
        try
        {
            var principal = ValidateTokenAndGetClaims(token);
            return principal?.Identity?.Name
                ?? principal?.Claims.FirstOrDefault(c => c.Type == ClaimTypes.NameIdentifier)?.Value
                ?? principal?.Claims.FirstOrDefault(c => c.Type == "sub")?.Value;
        }
        catch (Exception ex)
        {
            _logger.LogWarning("OAuth 2.0 token validation failed: {Message}", ex.Message);
            return null;
        }
    }

    public ClaimsPrincipal? ValidateTokenAndGetClaims(string token)
    {
        // Check if token is JWT or opaque
        if (IsJwtToken(token))
        {
            var principal = ValidateJwtToken(token);
            // For Google OAuth JWTs (ID tokens), add role claims if missing
            if (principal != null && _settings.Provider.Equals("Google", StringComparison.OrdinalIgnoreCase))
            {
                AddDefaultRoleIfMissing(principal);
            }
            return principal;
        }

        // For Google access tokens (opaque), verify via tokeninfo endpoint
        if (_settings.Provider.Equals("Google", StringComparison.OrdinalIgnoreCase))
        {
            return ValidateGoogleAccessToken(token);
        }

        // For other opaque tokens, use introspection if configured
        if (_settings.UseTokenIntrospection)
        {
            return IntrospectToken(token);
        }

        _logger.LogWarning("Token is not a valid JWT and introspection is not enabled");
        return null;
    }

    private void AddDefaultRoleIfMissing(ClaimsPrincipal principal)
    {
        var identity = principal.Identity as ClaimsIdentity;
        if (identity != null && !principal.HasClaim(c => c.Type == ClaimTypes.Role || c.Type == "role"))
        {
            identity.AddClaim(new Claim(ClaimTypes.Role, "User"));
            identity.AddClaim(new Claim("role", "User"));
            _logger.LogInformation("Added default 'User' role to Google OAuth user: {Email}",
                principal.FindFirst("email")?.Value ?? "unknown");
        }
    }

    private ClaimsPrincipal? ValidateGoogleAccessToken(string accessToken)
    {
        try
        {
            // Google access tokens can be validated via tokeninfo endpoint
            var tokenInfoUrl = $"https://oauth2.googleapis.com/tokeninfo?access_token={Uri.EscapeDataString(accessToken)}";
            var response = _httpClient.GetAsync(tokenInfoUrl).Result;

            if (!response.IsSuccessStatusCode)
            {
                var errorContent = response.Content.ReadAsStringAsync().Result;
                _logger.LogWarning("Google token validation failed: {StatusCode} - {Error}",
                    response.StatusCode, errorContent);
                return null;
            }

            var tokenInfoJson = response.Content.ReadAsStringAsync().Result;
            var tokenInfo = JsonSerializer.Deserialize<JsonElement>(tokenInfoJson);

            // Validate audience matches our client ID
            var audience = tokenInfo.GetProperty("aud").GetString();
            if (audience != _settings.ClientId && audience != _settings.Audience)
            {
                _logger.LogWarning("Google token audience mismatch. Expected: {Expected}, Got: {Actual}",
                    _settings.Audience ?? _settings.ClientId, audience);
                return null;
            }

            // Check if token is expired
            if (tokenInfo.TryGetProperty("exp", out var expProp))
            {
                var exp = expProp.GetInt64();
                var now = DateTimeOffset.UtcNow.ToUnixTimeSeconds();
                if (now > exp)
                {
                    _logger.LogWarning("Google token has expired");
                    return null;
                }
            }

            // Build claims from token info
            var claims = new List<Claim>
            {
                new Claim("sub", tokenInfo.GetProperty("sub").GetString() ?? ""),
                new Claim("aud", audience ?? "")
            };

            if (tokenInfo.TryGetProperty("email", out var emailProp))
                claims.Add(new Claim("email", emailProp.GetString() ?? ""));

            if (tokenInfo.TryGetProperty("email_verified", out var emailVerifiedProp))
                claims.Add(new Claim("email_verified", emailVerifiedProp.GetString() ?? ""));

            if (tokenInfo.TryGetProperty("name", out var nameProp))
                claims.Add(new Claim("name", nameProp.GetString() ?? ""));

            if (tokenInfo.TryGetProperty("picture", out var pictureProp))
                claims.Add(new Claim("picture", pictureProp.GetString() ?? ""));

            if (tokenInfo.TryGetProperty("scope", out var scopeProp))
            {
                var scopes = scopeProp.GetString()?.Split(' ') ?? Array.Empty<string>();
                foreach (var scope in scopes)
                {
                    if (!string.IsNullOrEmpty(scope))
                        claims.Add(new Claim("scope", scope));
                }
            }

            // Add role claims based on email or domain (custom logic can be added here)
            // Add multiple formats to ensure compatibility with authorization policies
            claims.Add(new Claim(ClaimTypes.Role, "User"));
            claims.Add(new Claim("role", "User"));
            claims.Add(new Claim("roles", "User"));

            var identity = new ClaimsIdentity(claims, "Google OAuth");
            _logger.LogInformation("Google access token validated for user: {Email}",
                claims.FirstOrDefault(c => c.Type == "email")?.Value ?? "unknown");

            return new ClaimsPrincipal(identity);
        }
        catch (Exception ex)
        {
            _logger.LogWarning("Google access token validation failed: {Message}", ex.Message);
            return null;
        }
    }

    private bool IsJwtToken(string token)
    {
        // JWT tokens have 3 parts separated by dots
        var parts = token.Split('.');
        return parts.Length == 3;
    }

    private ClaimsPrincipal? ValidateJwtToken(string token)
    {
        try
        {
            var config = _configManager.GetConfigurationAsync(CancellationToken.None).Result;

            var validationParameters = new TokenValidationParameters
            {
                ValidateIssuer = _settings.ValidateIssuer,
                ValidIssuer = config.Issuer,
                ValidateAudience = _settings.ValidateAudience,
                ValidAudience = _settings.Audience ?? _settings.ClientId,
                ValidateIssuerSigningKey = true,
                IssuerSigningKeys = config.SigningKeys,
                ValidateLifetime = _settings.ValidateLifetime,
                ClockSkew = TimeSpan.FromMinutes(5)
            };

            var tokenHandler = new JwtSecurityTokenHandler();
            var principal = tokenHandler.ValidateToken(token, validationParameters, out SecurityToken validatedToken);

            var jwtToken = (JwtSecurityToken)validatedToken;
            _logger.LogInformation("OAuth 2.0 JWT token validated. Subject: {Subject}, Issuer: {Issuer}, Expires: {Expires}",
                jwtToken.Subject,
                jwtToken.Issuer,
                jwtToken.ValidTo);

            return principal;
        }
        catch (Exception ex)
        {
            _logger.LogWarning("JWT validation failed: {Message}", ex.Message);
            return null;
        }
    }

    private ClaimsPrincipal? IntrospectToken(string token)
    {
        try
        {
            var config = _configManager.GetConfigurationAsync(CancellationToken.None).Result;
            var introspectionEndpoint = _settings.IntrospectionEndpoint ?? config.AdditionalData["introspection_endpoint"]?.ToString();

            if (string.IsNullOrEmpty(introspectionEndpoint))
            {
                _logger.LogError("Token introspection endpoint not available");
                return null;
            }

            var request = new HttpRequestMessage(HttpMethod.Post, introspectionEndpoint);
            request.Headers.Authorization = new AuthenticationHeaderValue("Basic",
                Convert.ToBase64String(System.Text.Encoding.UTF8.GetBytes($"{_settings.ClientId}:{_settings.ClientSecret}")));

            var content = new FormUrlEncodedContent(new Dictionary<string, string>
            {
                ["token"] = token,
                ["token_type_hint"] = "access_token"
            });
            request.Content = content;

            var response = _httpClient.SendAsync(request).Result;
            if (!response.IsSuccessStatusCode)
            {
                _logger.LogWarning("Token introspection failed: {StatusCode}", response.StatusCode);
                return null;
            }

            var jsonResponse = response.Content.ReadAsStringAsync().Result;
            var introspectionResult = JsonSerializer.Deserialize<JsonElement>(jsonResponse);

            if (!introspectionResult.GetProperty("active").GetBoolean())
            {
                _logger.LogWarning("Token is not active according to introspection endpoint");
                return null;
            }

            // Build claims from introspection response
            var claims = new List<Claim>();
            foreach (var property in introspectionResult.EnumerateObject())
            {
                if (property.Name != "active")
                {
                    claims.Add(new Claim(property.Name, property.Value.ToString()));
                }
            }

            var identity = new ClaimsIdentity(claims, "OAuth 2.0 Introspection");
            _logger.LogInformation("OAuth 2.0 opaque token validated via introspection. Subject: {Subject}",
                claims.FirstOrDefault(c => c.Type == "sub")?.Value ?? "unknown");

            return new ClaimsPrincipal(identity);
        }
        catch (Exception ex)
        {
            _logger.LogWarning("Token introspection failed: {Message}", ex.Message);
            return null;
        }
    }

    /// <summary>
    /// Get OAuth 2.0 discovery document information
    /// </summary>
    public async Task<Dictionary<string, object?>> GetDiscoveryDocumentAsync()
    {
        var config = await _configManager.GetConfigurationAsync(CancellationToken.None);
        config.AdditionalData.TryGetValue("end_session_endpoint", out var endSession);
        config.AdditionalData.TryGetValue("introspection_endpoint", out var introspection);
        config.AdditionalData.TryGetValue("revocation_endpoint", out var revocation);

        return new Dictionary<string, object?>
        {
            ["issuer"] = config.Issuer,
            ["authorization_endpoint"] = config.AuthorizationEndpoint,
            ["token_endpoint"] = config.TokenEndpoint,
            ["userinfo_endpoint"] = config.UserInfoEndpoint,
            ["end_session_endpoint"] = endSession,
            ["introspection_endpoint"] = introspection,
            ["revocation_endpoint"] = revocation
        };
    }
}
