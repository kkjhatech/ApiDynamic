using DyApi.Models;
using DyApi.Services;
using System.Security.Claims;
using System.Text.Json;

namespace DyApi.Middleware;

public class DynamicRoutingMiddleware
{
    private readonly RequestDelegate _next;
    private readonly ILogger<DynamicRoutingMiddleware> _logger;

    public DynamicRoutingMiddleware(RequestDelegate next, ILogger<DynamicRoutingMiddleware> logger)
    {
        _next = next;
        _logger = logger;
    }

    public async Task InvokeAsync(HttpContext context, IEndpointConfigService configService, IDynamicQueryService queryService, ITokenValidationService tokenValidationService, ISMSService? smsService = null)
    {
        var request = context.Request;
        var path = request.Path.Value?.TrimStart('/') ?? "";
        var method = request.Method.ToUpperInvariant();

        _logger.LogDebug("Processing request: {Method} {Path}", method, path);

        var config = await configService.GetEndpointByRouteAndVerbAsync(path, method);

        if (config == null)
        {
            await _next(context);
            return;
        }

        _logger.LogInformation("Matched dynamic endpoint: {MethodName} ({HttpVerb} {Route})", 
            config.MethodName, config.HttpVerb, config.RouteTemplate);

        // Check authorization if RequiredRole is set
        if (!string.IsNullOrEmpty(config.RequiredRole))
        {
            var authResult = await AuthorizeRequestAsync(context, config.RequiredRole, tokenValidationService);
            if (!authResult.IsAuthorized)
            {
                context.Response.StatusCode = authResult.StatusCode;
                context.Response.ContentType = "application/json";
                await context.Response.WriteAsync(JsonSerializer.Serialize(ApiResponse.ErrorResponse(authResult.ErrorMessage!)));
                return;
            }
        }

        try
        {
            var parameters = await ExtractParametersAsync(context, config);
            var validationError = ValidateParameters(config, parameters);
            
            if (!string.IsNullOrEmpty(validationError))
            {
                context.Response.StatusCode = StatusCodes.Status400BadRequest;
                context.Response.ContentType = "application/json";
                await context.Response.WriteAsync(JsonSerializer.Serialize(ApiResponse.ErrorResponse(validationError)));
                return;
            }

            var maskedParams = parameters.ToDictionary(
                kvp => kvp.Key, 
                kvp => IsSensitive(kvp.Key) ? "***" : kvp.Value?.ToString() ?? "null");
            
            _logger.LogInformation("Calling {StoredProcedure} with parameters: {Parameters}", 
                config.StoredProcedureName, JsonSerializer.Serialize(maskedParams));

            var result = await queryService.ExecuteStoredProcedureAsync(config.StoredProcedureName, parameters);

            // Handle SMS API call if configured (POST only - smsService is null for other methods)
            if (smsService != null && config.APICall?.Equals("SMS", StringComparison.OrdinalIgnoreCase) == true)
            {
                var phoneNumber = GetPhoneNumberFromResult(result, parameters);
                if (!string.IsNullOrEmpty(phoneNumber))
                {
                    var message = FormatSMSMessage(config.MethodName, result, parameters);
                    await smsService.SendSMSAsync(phoneNumber, message);
                }
            }

            context.Response.ContentType = "application/json";
            await context.Response.WriteAsync(JsonSerializer.Serialize(ApiResponse.SuccessResponse(result)));
        }
        catch (Exception ex)
        {
            _logger.LogError(ex, "Error processing dynamic endpoint {MethodName}", config.MethodName);
            
            context.Response.StatusCode = StatusCodes.Status500InternalServerError;
            context.Response.ContentType = "application/json";
            await context.Response.WriteAsync(JsonSerializer.Serialize(ApiResponse.ErrorResponse(
                "An error occurred while processing your request.")));
        }
    }

    private static void SetNestedParameter(Dictionary<string, object?> parameters, string keyPath, JsonElement value)
    {
        var parts = keyPath.Split('.');
        var currentDict = parameters;

        // Navigate to the parent object
        for (int i = 0; i < parts.Length - 1; i++)
        {
            var part = parts[i];
            if (!currentDict.TryGetValue(part, out var nestedObj) || nestedObj == null)
            {
                var newDict = new Dictionary<string, object?>(StringComparer.OrdinalIgnoreCase);
                currentDict[part] = newDict;
                currentDict = newDict;
            }
            else if (nestedObj is Dictionary<string, object?> nestedDict)
            {
                currentDict = nestedDict;
            }
            else
            {
                // Overwrite with new dictionary
                var newDict = new Dictionary<string, object?>(StringComparer.OrdinalIgnoreCase);
                currentDict[part] = newDict;
                currentDict = newDict;
            }
        }

        // Set the final value
        var finalKey = parts.Last();
        currentDict[finalKey] = value.ValueKind switch
        {
            JsonValueKind.String => value.GetString(),
            JsonValueKind.Number => value.TryGetInt64(out var longVal)
                ? longVal
                : value.GetDouble(),
            JsonValueKind.True => true,
            JsonValueKind.False => false,
            JsonValueKind.Null => null,
            JsonValueKind.Object => value.GetRawText(), // For complex nested objects, store as JSON string
            JsonValueKind.Array => value.GetRawText(),  // For arrays, store as JSON string
            _ => value.ToString()
        };
    }

    private static Task<AuthResult> AuthorizeRequestAsync(HttpContext context, string requiredRole, ITokenValidationService tokenValidationService)
    {
        var authHeader = context.Request.Headers.Authorization.FirstOrDefault();

        if (string.IsNullOrEmpty(authHeader) || !authHeader.StartsWith("Bearer ", StringComparison.OrdinalIgnoreCase))
        {
            return Task.FromResult(new AuthResult { IsAuthorized = false, StatusCode = StatusCodes.Status401Unauthorized, ErrorMessage = "Authorization header missing or invalid." });
        }

        var token = authHeader.Substring("Bearer ".Length).Trim();
        var claimsPrincipal = tokenValidationService.ValidateTokenAndGetClaims(token);

        if (claimsPrincipal == null)
        {
            return Task.FromResult(new AuthResult { IsAuthorized = false, StatusCode = StatusCodes.Status401Unauthorized, ErrorMessage = "Invalid or expired token." });
        }

        // Add default User role if no role exists (for OAuth tokens like Google that don't include roles)
        var identity = claimsPrincipal.Identity as ClaimsIdentity;
        if (identity != null && !claimsPrincipal.HasClaim(c => c.Type == ClaimTypes.Role || c.Type == "role"))
        {
            identity.AddClaim(new Claim(ClaimTypes.Role, "User"));
            identity.AddClaim(new Claim("role", "User"));
        }

        // Check role (matches policy: Admin can access User endpoints too)
        if (!string.IsNullOrEmpty(requiredRole))
        {
            // Check if user has required role using claims from the validated token
            var hasRequiredRole = claimsPrincipal.IsInRole(requiredRole) ||
                                  claimsPrincipal.HasClaim(ClaimTypes.Role, requiredRole);

            var isAdmin = claimsPrincipal.IsInRole("Admin") ||
                          claimsPrincipal.HasClaim(ClaimTypes.Role, "Admin");

            var authorized = hasRequiredRole || (requiredRole == "User" && isAdmin);

            if (!authorized)
            {
                return Task.FromResult(new AuthResult { IsAuthorized = false, StatusCode = StatusCodes.Status403Forbidden, ErrorMessage = $"Required role '{requiredRole}' not found." });
            }
        }

        return Task.FromResult(new AuthResult { IsAuthorized = true });
    }

    private class AuthResult
    {
        public bool IsAuthorized { get; set; }
        public int StatusCode { get; set; }
        public string? ErrorMessage { get; set; }
    }

    private static async Task<Dictionary<string, object?>> ExtractParametersAsync(HttpContext context, ApiEndpointConfig config)
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
                            // Handle nested parameter names like "user.profile.age"
                            if (config.GetParameterNames().Any(p => p.Contains(".")) &&
                                property.Name.Contains("."))
                            {
                                SetNestedParameter(parameters, property.Name, property.Value);
                            }
                            else if (property.Name == "data" &&
                                     config.GetParameterNames().Any(p => p.Contains(".")))
                            {
                                // Handle cases where parameter is wrapped in "data"
                                foreach (var paramProp in property.Value.EnumerateObject())
                                {
                                    if (config.GetParameterNames().Any(p => p.Contains(".")) &&
                                        paramProp.Name.Contains("."))
                                    {
                                        SetNestedParameter(parameters, paramProp.Name, paramProp.Value);
                                    }
                                    else
                                    {
                                        parameters[paramProp.Name] = paramProp.Value.ValueKind switch
                                        {
                                            JsonValueKind.String => paramProp.Value.GetString(),
                                            JsonValueKind.Number => paramProp.Value.TryGetInt64(out var longVal)
                                                ? longVal
                                                : paramProp.Value.GetDouble(),
                                            JsonValueKind.True => true,
                                            JsonValueKind.False => false,
                                            JsonValueKind.Null => null,
                                            _ => paramProp.Value.ToString()
                                        };
                                    }
                                }
                            }
                            else
                            {
                                parameters[property.Name] = property.Value.ValueKind switch
                                {
                                    JsonValueKind.String => property.Value.GetString(),
                                    JsonValueKind.Number => property.Value.TryGetInt64(out var longVal)
                                        ? longVal
                                        : property.Value.GetDouble(),
                                    JsonValueKind.True => true,
                                    JsonValueKind.False => false,
                                    JsonValueKind.Null => null,
                                    _ => property.Value.ToString()
                                };
                            }
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

    private static string? ValidateParameters(ApiEndpointConfig config, Dictionary<string, object?> parameters)
    {
        var requiredParams = config.GetParameterNames();
        var missingParams = new List<string>();

        foreach (var param in requiredParams)
        {
            if (!parameters.ContainsKey(param) || parameters[param] == null)
            {
                missingParams.Add(param);
            }
        }

        return missingParams.Count > 0 
            ? $"Missing required parameters: {string.Join(", ", missingParams)}" 
            : null;
    }

    private static bool IsSensitive(string paramName)
    {
        var sensitiveKeywords = new[] { "password", "secret", "token", "key", "credential", "auth" };
        return sensitiveKeywords.Any(keyword => 
            paramName.Contains(keyword, StringComparison.OrdinalIgnoreCase));
    }

    private static string? GetPhoneNumberFromResult(object? result, Dictionary<string, object?> parameters)
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

    private static string FormatSMSMessage(string methodName, object? result, Dictionary<string, object?> parameters)
    {
        return $"API {methodName} executed successfully.";
    }
}
