namespace DyApi.Models;

public class OAuthSettings
{
    public string Provider { get; set; } = "Generic"; // Google, Microsoft, Auth0, Okta, etc.
    public string Authority { get; set; } = string.Empty;
    public string ClientId { get; set; } = string.Empty;
    public string? ClientSecret { get; set; }
    public string? Audience { get; set; }
    public string Scopes { get; set; } = "openid profile email";

    // OAuth 2.0 endpoints (auto-discovered if not specified)
    public string? AuthorizationEndpoint { get; set; }
    public string? TokenEndpoint { get; set; }
    public string? IntrospectionEndpoint { get; set; }
    public string? UserInfoEndpoint { get; set; }

    // Validation options
    public bool ValidateIssuer { get; set; } = true;
    public bool ValidateAudience { get; set; } = true;
    public bool ValidateLifetime { get; set; } = true;
    public bool RequireHttpsMetadata { get; set; } = true;

    // Token introspection (for opaque tokens)
    public bool UseTokenIntrospection { get; set; } = false;

    // Cache duration for discovery document (minutes)
    public int DiscoveryCacheDurationMinutes { get; set; } = 60;
}
