using DyApi.Middleware;
using DyApi.Models;
using DyApi.Services;
using System.Data.SqlClient;
using System.Security.Claims;
using Microsoft.AspNetCore.Authentication.JwtBearer;
using Microsoft.IdentityModel.Tokens;
using Microsoft.OpenApi.Models;
using Microsoft.AspNetCore.Mvc;
using System.Text;
using System.Text.Json;

var builder = WebApplication.CreateBuilder(args);

// Add services
builder.Services.AddMemoryCache();
builder.Services.AddSingleton<IEndpointConfigService, EndpointConfigService>();
builder.Services.AddScoped<IDynamicQueryService, DynamicQueryService>();
builder.Services.AddScoped<IJwtService, JwtService>();
builder.Services.AddScoped<IAuthService, AuthService>();
builder.Services.AddScoped<ISMSService, SMSService>();

// Configure Authentication Provider (JWT or OAuth)
var authProvider = builder.Configuration.GetValue<string>("AuthProvider") ?? "JWT";
var jwtSettings = builder.Configuration.GetSection("Jwt").Get<JwtSettings>();
var oauthSettings = builder.Configuration.GetSection("OAuth").Get<OAuthSettings>();

if (authProvider.Equals("OAuth", StringComparison.OrdinalIgnoreCase))
{
    if (oauthSettings == null || string.IsNullOrEmpty(oauthSettings.Authority))
    {
        throw new InvalidOperationException("OAuth settings not configured properly. Please check appsettings.json");
    }

    // OAuth 2.0 Authentication
    builder.Services.AddScoped<ITokenValidationService, OAuthTokenValidationService>();
    builder.Services.AddAuthentication(options =>
    {
        options.DefaultAuthenticateScheme = JwtBearerDefaults.AuthenticationScheme;
        options.DefaultChallengeScheme = JwtBearerDefaults.AuthenticationScheme;
    })
    .AddJwtBearer(options =>
    {
        options.Authority = oauthSettings.Authority;
        // For Google OAuth, access tokens are opaque (not JWT) and validated via tokeninfo endpoint
        // We disable audience validation here and handle it in OAuthTokenValidationService
        options.Audience = oauthSettings.Audience ?? oauthSettings.ClientId;
        options.RequireHttpsMetadata = oauthSettings.RequireHttpsMetadata;
        options.TokenValidationParameters = new TokenValidationParameters
        {
            ValidateIssuer = oauthSettings.ValidateIssuer,
            // For Google, disable audience validation since access tokens are for Google APIs
            ValidateAudience = oauthSettings.Provider != "Google" && oauthSettings.ValidateAudience,
            ValidateLifetime = oauthSettings.ValidateLifetime,
            ValidateIssuerSigningKey = true,
            ClockSkew = TimeSpan.FromMinutes(5)
        };

        // Add role claims for Google OAuth tokens (they don't include roles by default)
        options.Events = new JwtBearerEvents
        {
            OnTokenValidated = context =>
            {
                var identity = context.Principal?.Identity as ClaimsIdentity;
                if (identity != null && !identity.HasClaim(c => c.Type == ClaimTypes.Role || c.Type == "role"))
                {
                    identity.AddClaim(new Claim(ClaimTypes.Role, "User"));
                    identity.AddClaim(new Claim("role", "User"));
                }
                return Task.CompletedTask;
            }
        };
    });

    builder.Services.AddAuthorization(options =>
    {
        // OAuth uses claims-based authorization
        options.AddPolicy("Admin", policy => policy.RequireAssertion(context =>
            context.User.IsInRole("Admin") ||
            context.User.IsInRole("admin") ||
            context.User.IsInRole("Administrator") ||
            context.User.HasClaim(System.Security.Claims.ClaimTypes.Role, "Admin") ||
            context.User.HasClaim("role", "Admin") ||
            context.User.HasClaim("roles", "Admin")));
        options.AddPolicy("User", policy => policy.RequireAssertion(context =>
            context.User.IsInRole("User") ||
            context.User.IsInRole("user") ||
            context.User.IsInRole("Admin") ||
            context.User.IsInRole("admin") ||
            context.User.HasClaim(System.Security.Claims.ClaimTypes.Role, "User") ||
            context.User.HasClaim("role", "User") ||
            context.User.HasClaim("role", "Admin") ||
            context.User.HasClaim("roles", "User") ||
            context.User.HasClaim("roles", "Admin")));
    });

    Console.WriteLine($"Authentication configured: OAuth 2.0 (Provider: {oauthSettings.Provider}, Authority: {oauthSettings.Authority})");
}
else
{
    // JWT Authentication (default)
    builder.Services.AddScoped<ITokenValidationService, JwtTokenValidationService>();

    if (jwtSettings != null)
    {
        builder.Services.AddAuthentication(JwtBearerDefaults.AuthenticationScheme)
            .AddJwtBearer(options =>
            {
                // CRITICAL: For local JWT, disable OIDC discovery by clearing all OAuth-related settings
                options.Authority = null;
                options.Audience = null;
                options.MetadataAddress = null;

                // Use ONLY local symmetric key validation
                options.TokenValidationParameters = new TokenValidationParameters
                {
                    ValidateIssuer = true,
                    ValidIssuer = jwtSettings.Issuer,
                    ValidateAudience = true,
                    ValidAudience = jwtSettings.Audience,
                    ValidateLifetime = true,
                    ValidateIssuerSigningKey = true,
                    IssuerSigningKey = new SymmetricSecurityKey(Encoding.UTF8.GetBytes(jwtSettings.SecretKey)),
                    ClockSkew = TimeSpan.Zero
                };

                // Add event handlers for debugging
                options.Events = new JwtBearerEvents
                {
                    OnAuthenticationFailed = context =>
                    {
                        Console.WriteLine($"JWT Authentication failed: {context.Exception.Message}");
                        return Task.CompletedTask;
                    },
                    OnTokenValidated = context =>
                    {
                        Console.WriteLine($"JWT Token validated for user: {context.Principal?.Identity?.Name}");
                        return Task.CompletedTask;
                    }
                };
            });

        builder.Services.AddAuthorization(options =>
        {
            options.AddPolicy("Admin", policy => policy.RequireRole("Admin"));
            options.AddPolicy("User", policy => policy.RequireRole("User", "Admin"));
        });

        Console.WriteLine($"Authentication configured: LOCAL JWT");
        Console.WriteLine($"  Expected Issuer: {jwtSettings.Issuer}");
        Console.WriteLine($"  Expected Audience: {jwtSettings.Audience}");
        Console.WriteLine($"  Token source: /api/login endpoint");
        Console.WriteLine($"  IMPORTANT: Google OAuth tokens will NOT work in JWT mode!");
    }
}

builder.Services.AddControllers();
builder.Services.AddEndpointsApiExplorer();

// Configure Swagger
builder.Services.AddSwaggerGen(options =>
{
    options.SwaggerDoc("v1", new OpenApiInfo
    {
        Title = "Dynamic API",
        Version = "v1",
        Description = "A fully dynamic Web API with configurable endpoints"
    });

    // Bearer Token Authentication (JWT or OAuth)
    var authProviderForSwagger = builder.Configuration.GetValue<string>("AuthProvider") ?? "JWT";
    var bearerDescription = authProviderForSwagger.Equals("OAuth", StringComparison.OrdinalIgnoreCase)
        ? "OAuth 2.0 Bearer token. Example: \"Bearer {token}\""
        : "JWT Bearer token. Example: \"Bearer {token}\"";

    options.AddSecurityDefinition("Bearer", new OpenApiSecurityScheme
    {
        Type = SecuritySchemeType.Http,
        Scheme = "bearer",
        BearerFormat = authProviderForSwagger.Equals("OAuth", StringComparison.OrdinalIgnoreCase) ? "OAuth 2.0" : "JWT",
        In = ParameterLocation.Header,
        Name = "Authorization",
        Description = bearerDescription
    });

    // API Key Authentication (for admin endpoints)
    options.AddSecurityDefinition("ApiKey", new OpenApiSecurityScheme
    {
        Type = SecuritySchemeType.ApiKey,
        In = ParameterLocation.Header,
        Name = "X-Admin-Api-Key",
        Description = "Admin API Key for protected endpoints"
    });

    options.AddSecurityRequirement(new OpenApiSecurityRequirement
    {
        {
            new OpenApiSecurityScheme
            {
                Reference = new OpenApiReference
                {
                    Type = ReferenceType.SecurityScheme,
                    Id = "Bearer"
                }
            },
            Array.Empty<string>()
        }
    });

    // Custom document filter to add dynamic endpoints
    options.DocumentFilter<DynamicEndpointDocumentFilter>();
});

var app = builder.Build();

// Ensure configuration is loaded at startup
using (var scope = app.Services.CreateScope())
{
    var configService = scope.ServiceProvider.GetRequiredService<IEndpointConfigService>();
    await configService.ReloadCacheAsync();
}

// Configure middleware pipeline
if (app.Environment.IsDevelopment())
{
    app.UseSwagger();
    app.UseSwaggerUI();
}

app.UseHttpsRedirection();
app.UseAuthentication();
app.UseAuthorization();

// Map authentication endpoints
MapAuthEndpoints(app);

// Map admin routes before dynamic middleware
app.MapPost("/api/reload-config", async (HttpContext context, IEndpointConfigService configService, IConfiguration configuration) =>
{
    var apiKey = context.Request.Headers["X-Admin-Api-Key"].FirstOrDefault();
    var expectedApiKey = configuration["AdminApiKey"];

    if (string.IsNullOrEmpty(apiKey) || apiKey != expectedApiKey)
    {
        context.Response.StatusCode = StatusCodes.Status401Unauthorized;
        context.Response.ContentType = "application/json";
        await context.Response.WriteAsync(JsonSerializer.Serialize(ApiResponse.ErrorResponse("Invalid or missing API key.")));
        return;
    }

    try
    {
        await configService.ReloadCacheAsync();
        context.Response.ContentType = "application/json";
        await context.Response.WriteAsync(JsonSerializer.Serialize(ApiResponse.SuccessResponse(new { message = "Configuration reloaded successfully." })));
    }
    catch (Exception ex)
    {
        context.Response.StatusCode = StatusCodes.Status500InternalServerError;
        context.Response.ContentType = "application/json";
        await context.Response.WriteAsync(JsonSerializer.Serialize(ApiResponse.ErrorResponse($"Failed to reload configuration: {ex.Message}")));
    }
})
.WithName("ReloadConfig")
.WithOpenApi(operation =>
{
    operation.Summary = "Reload API endpoint configuration cache";
    operation.Description = @"Clears and reloads the endpoint configuration cache from the database. 

NOTE: This only affects endpoints handled by the middleware fallback. 
Endpoints registered at startup (shown in logs at application start) are fixed until restart.

Call this endpoint after adding NEW endpoints to the database while the app is running.";
    return operation;
});

// Health check endpoint
app.MapGet("/api/health", (IEndpointConfigService configService) =>
{
    var configs = configService.GetCachedEndpoints();
    return Results.Json(ApiResponse.SuccessResponse(new 
    { 
        status = "Healthy", 
        endpointsLoaded = configs.Count,
        timestamp = DateTime.UtcNow.AddHours(5.5)
    }));
})
.WithName("HealthCheck")
.WithOpenApi(operation =>
{
    operation.Summary = "Health check";
    operation.Description = "Returns the health status of the API and the number of loaded endpoints.";
    return operation;
});

// Register dynamic endpoints using minimal APIs (AT STARTUP ONLY)
// Endpoints in the database at startup are registered directly for better performance
// New endpoints added while running will be handled by DynamicRoutingMiddleware after cache reload
var endpointConfigService = app.Services.GetRequiredService<IEndpointConfigService>();
var endpoints = await endpointConfigService.GetAllEndpointsAsync();

foreach (var endpoint in endpoints)
{
    RegisterDynamicEndpoint(app, endpoint);
}

// Add fallback middleware for routes not registered at startup
// This handles: new endpoints added after startup, or endpoints that need cache refresh
// Call POST /api/reload-config to refresh cache when adding new endpoints to database
app.UseMiddleware<DynamicRoutingMiddleware>();

app.Run();

// Authentication endpoints
void MapAuthEndpoints(WebApplication app)
{
    // Login endpoint
    app.MapPost("/api/auth/login", async (LoginRequest request, IAuthService authService) =>
    {
        if (string.IsNullOrEmpty(request.Username) || string.IsNullOrEmpty(request.Password))
        {
            return Results.BadRequest(ApiResponse.ErrorResponse("Username and password are required."));
        }

        var response = await authService.LoginAsync(request);
        
        if (response == null)
        {
            return Results.Unauthorized();
        }

        return Results.Ok(ApiResponse.SuccessResponse(response));
    })
    .WithName("Login")
    .WithOpenApi(operation =>
    {
        operation.Summary = "User login";
        operation.Description = "Authenticate user and receive access token and refresh token.";
        return operation;
    });

    // Refresh token endpoint
    app.MapPost("/api/auth/refresh", async (RefreshTokenRequest request, IJwtService jwtService) =>
    {
        if (string.IsNullOrEmpty(request.RefreshToken))
        {
            return Results.BadRequest(ApiResponse.ErrorResponse("Refresh token is required."));
        }

        var response = await jwtService.RefreshTokensAsync(request.RefreshToken);
        
        if (response == null)
        {
            return Results.Unauthorized();
        }

        return Results.Ok(ApiResponse.SuccessResponse(response));
    })
    .WithName("RefreshToken")
    .WithOpenApi(operation =>
    {
        operation.Summary = "Refresh access token";
        operation.Description = "Get a new access token using a valid refresh token.";
        return operation;
    });

    // Logout endpoint
    app.MapPost("/api/auth/logout", async (RefreshTokenRequest request, IAuthService authService) =>
    {
        if (string.IsNullOrEmpty(request.RefreshToken))
        {
            return Results.BadRequest(ApiResponse.ErrorResponse("Refresh token is required."));
        }

        var success = await authService.LogoutAsync(request.RefreshToken);
        
        if (!success)
        {
            return Results.BadRequest(ApiResponse.ErrorResponse("Invalid refresh token."));
        }

        return Results.Ok(ApiResponse.SuccessResponse(new { message = "Logged out successfully." }));
    })
    .WithName("Logout")
    .WithOpenApi(operation =>
    {
        operation.Summary = "User logout";
        operation.Description = "Revoke the refresh token to logout.";
        return operation;
    });

    // Register endpoint (admin only)
    app.MapPost("/api/auth/register", [Microsoft.AspNetCore.Authorization.Authorize(Roles = "Admin")] async (User user, string password, IAuthService authService) =>
    {
        if (string.IsNullOrEmpty(user.Username) || string.IsNullOrEmpty(password))
        {
            return Results.BadRequest(ApiResponse.ErrorResponse("Username and password are required."));
        }

        var success = await authService.RegisterAsync(user, password);
        
        if (!success)
        {
            return Results.BadRequest(ApiResponse.ErrorResponse("Username already exists or registration failed."));
        }

        return Results.Ok(ApiResponse.SuccessResponse(new { message = "User registered successfully." }));
    })
    .WithName("Register")
    .WithOpenApi(operation =>
    {
        operation.Summary = "Register new user (Admin only)";
        operation.Description = "Create a new user account. Requires Admin role.";
        return operation;
    });

    // Google OAuth Login - Step 1: Initiate OAuth flow
    app.MapGet("/api/auth/google", (IConfiguration config, HttpContext context) =>
    {
        var oauthSettings = config.GetSection("OAuth").Get<OAuthSettings>();
        if (oauthSettings == null || string.IsNullOrEmpty(oauthSettings.ClientId))
        {
            return Results.BadRequest(ApiResponse.ErrorResponse("OAuth not configured"));
        }

        // Build the Google OAuth URL
        var redirectUri = $"{context.Request.Scheme}://{context.Request.Host}/api/auth/google/callback";
        var state = Guid.NewGuid().ToString("N"); // Generate random state for security

        // Store state in session/cookie for validation (simplified - using query param for demo)
        var authUrl = $"https://accounts.google.com/o/oauth2/v2/auth?" +
            $"client_id={Uri.EscapeDataString(oauthSettings.ClientId)}&" +
            $"redirect_uri={Uri.EscapeDataString(redirectUri)}&" +
            $"response_type=code&" +
            $"scope={Uri.EscapeDataString(oauthSettings.Scopes)}&" +
            $"state={state}&" +
            $"access_type=offline&" +
            $"prompt=consent";

        return Results.Ok(ApiResponse.SuccessResponse(new
        {
            authUrl,
            redirectUri,
            state,
            message = "Open this URL in browser to login with Google"
        }));
    })
    .WithName("GoogleLogin")
    .WithOpenApi(operation =>
    {
        operation.Summary = "Initiate Google OAuth Login";
        operation.Description = "Returns the Google OAuth URL. Open this URL in browser to authenticate.";
        return operation;
    })
    .AllowAnonymous();

    // Google OAuth Login - Step 2: Handle callback
    app.MapGet("/api/auth/google/callback", async (
        [FromQuery] string code,
        [FromQuery] string? state,
        [FromQuery] string? error,
        IConfiguration config,
        HttpContext context,
        ILogger<Program> logger) =>
    {
        if (!string.IsNullOrEmpty(error))
        {
            logger.LogWarning("Google OAuth error: {Error}", error);
            return Results.BadRequest(ApiResponse.ErrorResponse($"Google authentication failed: {error}"));
        }

        if (string.IsNullOrEmpty(code))
        {
            return Results.BadRequest(ApiResponse.ErrorResponse("Authorization code not provided"));
        }

        var oauthSettings = config.GetSection("OAuth").Get<OAuthSettings>();
        if (oauthSettings == null || string.IsNullOrEmpty(oauthSettings.ClientId))
        {
            return Results.BadRequest(ApiResponse.ErrorResponse("OAuth not configured"));
        }

        try
        {
            // Exchange code for tokens
            var redirectUri = $"{context.Request.Scheme}://{context.Request.Host}/api/auth/google/callback";
            var tokenEndpoint = "https://oauth2.googleapis.com/token";

            using var httpClient = new HttpClient();
            var tokenRequest = new FormUrlEncodedContent(new Dictionary<string, string>
            {
                ["code"] = code,
                ["client_id"] = oauthSettings.ClientId,
                ["client_secret"] = oauthSettings.ClientSecret ?? "",
                ["redirect_uri"] = redirectUri,
                ["grant_type"] = "authorization_code"
            });

            var tokenResponse = await httpClient.PostAsync(tokenEndpoint, tokenRequest);
            var tokenContent = await tokenResponse.Content.ReadAsStringAsync();

            if (!tokenResponse.IsSuccessStatusCode)
            {
                logger.LogError("Token exchange failed: {Response}", tokenContent);
                return Results.BadRequest(ApiResponse.ErrorResponse("Failed to exchange authorization code"));
            }

            var tokenData = JsonSerializer.Deserialize<JsonElement>(tokenContent);
            var accessToken = tokenData.GetProperty("access_token").GetString();
            var idToken = tokenData.GetProperty("id_token").GetString();
            var expiresIn = tokenData.GetProperty("expires_in").GetInt32();

            // Get user info from Google
            var userInfoResponse = await httpClient.GetAsync($"https://www.googleapis.com/oauth2/v3/userinfo?access_token={accessToken}");
            var userInfoContent = await userInfoResponse.Content.ReadAsStringAsync();
            var userInfo = JsonSerializer.Deserialize<JsonElement>(userInfoContent);

            var userId = userInfo.GetProperty("sub").GetString();
            var email = userInfo.TryGetProperty("email", out var emailProp) ? emailProp.GetString() : null;
            var name = userInfo.TryGetProperty("name", out var nameProp) ? nameProp.GetString() : null;
            var picture = userInfo.TryGetProperty("picture", out var pictureProp) ? pictureProp.GetString() : null;

            logger.LogInformation("Google login successful for user: {Email}", email);

            return Results.Ok(ApiResponse.SuccessResponse(new
            {
                accessToken,
                idToken,
                expiresIn,
                tokenType = "Bearer",
                user = new
                {
                    id = userId,
                    email,
                    name,
                    picture
                },
                message = "Login successful! Use the accessToken as Bearer token in Authorization header"
            }));
        }
        catch (Exception ex)
        {
            logger.LogError(ex, "Google OAuth callback failed");
            return Results.StatusCode(500);
        }
    })
    .WithName("GoogleCallback")
    .WithOpenApi(operation =>
    {
        operation.Summary = "Google OAuth Callback";
        operation.Description = "Handles Google OAuth callback and returns access token. Do not call directly - this is called by Google after login.";
        return operation;
    })
    .AllowAnonymous();
}

// Helper method to register dynamic endpoints
void RegisterDynamicEndpoint(WebApplication app, ApiEndpointConfig config)
{
    var routePattern = config.RouteTemplate.TrimStart('/');
    var logger = app.Services.GetRequiredService<ILogger<Program>>();

    // Trim RequiredRole to handle database spaces
    var requiredRole = config.RequiredRole?.Trim();

    logger.LogInformation("Registering dynamic endpoint: {HttpVerb} {Route} -> {StoredProcedure} (Auth: {Auth})",
        config.HttpVerb, config.RouteTemplate, config.StoredProcedureName,
        string.IsNullOrEmpty(requiredRole) ? "None" : requiredRole);

    try
    {
        var requireAuth = !string.IsNullOrEmpty(requiredRole);

        switch (config.HttpVerb.ToUpperInvariant())
        {
            case "GET":
                var getEndpoint = app.MapGet(routePattern, async (HttpContext context, IDynamicQueryService queryService) =>
                {
                    return await HandleDynamicRequest(context, config, queryService, null);
                })
                .WithName(config.MethodName)
                .WithOpenApi(operation => BuildOpenApiOperation(operation, config));

                if (requireAuth)
                    getEndpoint.RequireAuthorization(requiredRole!);
                else
                    getEndpoint.AllowAnonymous();
                break;

            case "POST":
                var postEndpoint = app.MapPost(routePattern, async (HttpContext context, IDynamicQueryService queryService, ISMSService smsService) =>
                {
                    return await HandleDynamicRequest(context, config, queryService, smsService);
                })
                .WithName(config.MethodName)
                .WithOpenApi(operation => BuildOpenApiOperation(operation, config));

                if (requireAuth)
                    postEndpoint.RequireAuthorization(requiredRole!);
                else
                    postEndpoint.AllowAnonymous();
                break;

            case "PUT":
                var putEndpoint = app.MapPut(routePattern, async (HttpContext context, IDynamicQueryService queryService) =>
                {
                    return await HandleDynamicRequest(context, config, queryService, null);
                })
                .WithName(config.MethodName)
                .WithOpenApi(operation => BuildOpenApiOperation(operation, config));

                if (requireAuth)
                    putEndpoint.RequireAuthorization(requiredRole!);
                else
                    putEndpoint.AllowAnonymous();
                break;

            case "DELETE":
                var deleteEndpoint = app.MapDelete(routePattern, async (HttpContext context, IDynamicQueryService queryService) =>
                {
                    return await HandleDynamicRequest(context, config, queryService, null);
                })
                .WithName(config.MethodName)
                .WithOpenApi(operation => BuildOpenApiOperation(operation, config));

                if (requireAuth)
                    deleteEndpoint.RequireAuthorization(requiredRole!);
                else
                    deleteEndpoint.AllowAnonymous();
                break;

            case "PATCH":
                var patchEndpoint = app.MapPatch(routePattern, async (HttpContext context, IDynamicQueryService queryService) =>
                {
                    return await HandleDynamicRequest(context, config, queryService, null);
                })
                .WithName(config.MethodName)
                .WithOpenApi(operation => BuildOpenApiOperation(operation, config));

                if (requireAuth)
                    patchEndpoint.RequireAuthorization(requiredRole!);
                else
                    patchEndpoint.AllowAnonymous();
                break;

            default:
                logger.LogWarning("Unsupported HTTP verb: {HttpVerb} for endpoint {MethodName}", 
                    config.HttpVerb, config.MethodName);
                break;
        }
    }
    catch (Exception ex)
    {
        logger.LogError(ex, "Failed to register endpoint {MethodName}", config.MethodName);
    }
}

async Task<IResult> HandleDynamicRequest(HttpContext context, ApiEndpointConfig config, IDynamicQueryService queryService, ISMSService? smsService)
{
    try
    {
        var parameters = await ExtractParametersFromRequest(context, config);
        var validationError = ValidateRequiredParameters(config, parameters);

        if (!string.IsNullOrEmpty(validationError))
        {
            return Results.BadRequest(ApiResponse.ErrorResponse(validationError));
        }

        var result = await queryService.ExecuteStoredProcedureAsync(config.StoredProcedureName, parameters);

        // Handle SMS API call if configured (POST only)
        if (smsService != null && config.APICall?.Equals("SMS", StringComparison.OrdinalIgnoreCase) == true)
        {
            var phoneNumber = GetPhoneNumberFromResult(result, parameters);
            if (!string.IsNullOrEmpty(phoneNumber))
            {
                var message = FormatSMSMessage(config.MethodName, result, parameters);
                await smsService.SendSMSAsync(phoneNumber, message);
            }
        }

        return Results.Ok(ApiResponse.SuccessResponse(result));
    }
    catch (SqlException ex)
    {
        return Results.BadRequest(ApiResponse.ErrorResponse($"Database error: {ex.Message}"));
    }
    catch (Exception)
    {
        return Results.StatusCode(500);
    }
}

static string? GetPhoneNumberFromResult(object? result, Dictionary<string, object?> parameters)
{
    // Try to get phone number from result or parameters
    if (result is IEnumerable<dynamic> list && list.Any())
    {
        var first = list.First();
        if (first is IDictionary<string, object> dict)
        {
            var phoneKey = dict.Keys.FirstOrDefault(k => k.Contains("Phone", StringComparison.OrdinalIgnoreCase));
            if (phoneKey != null && dict[phoneKey] != null)
                return dict[phoneKey]?.ToString();
        }
    }

    var paramKey = parameters.Keys.FirstOrDefault(k => k.Contains("Phone", StringComparison.OrdinalIgnoreCase));
    return paramKey != null ? parameters[paramKey]?.ToString() : null;
}

static string FormatSMSMessage(string methodName, object? result, Dictionary<string, object?> parameters)
{
    return $"API {methodName} executed successfully.";
}

async Task<Dictionary<string, object?>> ExtractParametersFromRequest(HttpContext context, ApiEndpointConfig config)
{
    var parameters = new Dictionary<string, object?>(StringComparer.OrdinalIgnoreCase);
    var request = context.Request;
    var paramNames = config.GetParameterNames();

    foreach (var paramName in paramNames)
    {
        if (request.RouteValues.TryGetValue(paramName, out var routeValue) && routeValue != null)
        {
            parameters[paramName] = routeValue.ToString();
            continue;
        }

        if (request.Query.TryGetValue(paramName, out var queryValue) && queryValue.Count > 0)
        {
            parameters[paramName] = queryValue.FirstOrDefault();
            continue;
        }
    }

    if (config.HttpVerb is "POST" or "PUT" or "PATCH")
    {
        try
        {
            request.EnableBuffering();
            using var reader = new StreamReader(request.Body, leaveOpen: true);
            var body = await reader.ReadToEndAsync();
            request.Body.Position = 0;

            if (!string.IsNullOrWhiteSpace(body))
            {
                using var document = JsonDocument.Parse(body);
                var root = document.RootElement;

                if (root.ValueKind == JsonValueKind.Object)
                {
                    foreach (var property in root.EnumerateObject())
                    {
                        parameters[property.Name] = property.Value.ValueKind switch
                        {
                            JsonValueKind.String => property.Value.GetString(),
                            JsonValueKind.Number => property.Value.TryGetInt64(out var longVal) ? longVal : property.Value.GetDouble(),
                            JsonValueKind.True => true,
                            JsonValueKind.False => false,
                            JsonValueKind.Null => null,
                            _ => property.Value.ToString()
                        };
                    }
                }
            }
        }
        catch (JsonException)
        {
        }
    }

    return parameters;
}

string? ValidateRequiredParameters(ApiEndpointConfig config, Dictionary<string, object?> parameters)
{
    var requiredParams = config.GetParameterNames();
    var missingParams = requiredParams.Where(p => !parameters.ContainsKey(p) || parameters[p] == null).ToList();
    
    return missingParams.Count > 0 
        ? $"Missing required parameters: {string.Join(", ", missingParams)}" 
        : null;
}

OpenApiOperation BuildOpenApiOperation(OpenApiOperation operation, ApiEndpointConfig config)
{
    operation.Summary = config.MethodName;
    operation.Description = string.IsNullOrEmpty(config.Description) 
        ? $"Dynamic endpoint: {config.MethodName}" 
        : config.Description;

    var paramNames = config.GetParameterNames();
    foreach (var paramName in paramNames)
    {
        if (!operation.Parameters.Any(p => p.Name == paramName))
        {
            operation.Parameters.Add(new OpenApiParameter
            {
                Name = paramName,
                In = config.RouteTemplate.Contains($"{{{paramName}}}") ? ParameterLocation.Path : ParameterLocation.Query,
                Required = config.RouteTemplate.Contains($"{{{paramName}}}")
            });
        }
    }

    // Add JWT security requirement if endpoint requires authorization
    if (!string.IsNullOrEmpty(config.RequiredRole))
    {
        operation.Security = new List<OpenApiSecurityRequirement>
        {
            new OpenApiSecurityRequirement
            {
                {
                    new OpenApiSecurityScheme
                    {
                        Reference = new OpenApiReference
                        {
                            Type = ReferenceType.SecurityScheme,
                            Id = "Bearer"
                        }
                    },
                    Array.Empty<string>()
                }
            }
        };
    }

    return operation;
}

// Custom Swagger document filter for dynamic endpoints
public class DynamicEndpointDocumentFilter : Swashbuckle.AspNetCore.SwaggerGen.IDocumentFilter
{
    public void Apply(Microsoft.OpenApi.Models.OpenApiDocument swaggerDoc, Swashbuckle.AspNetCore.SwaggerGen.DocumentFilterContext context)
    {
    }
}
