using Dapper;
using DyApi.Models;
using System.Data.SqlClient;
using Microsoft.Extensions.Caching.Memory;

namespace DyApi.Services;

public class EndpointConfigService : IEndpointConfigService
{
    private readonly string _connectionString;
    private readonly IMemoryCache _cache;
    private readonly ILogger<EndpointConfigService> _logger;
    private const string CacheKey = "ApiEndpointConfigs";
    private static readonly TimeSpan CacheExpiration = TimeSpan.FromHours(1);

    public EndpointConfigService(IConfiguration configuration, IMemoryCache cache, ILogger<EndpointConfigService> logger)
    {
        _connectionString = configuration.GetConnectionString("DefaultConnection") 
            ?? throw new InvalidOperationException("DefaultConnection connection string not found.");
        _cache = cache;
        _logger = logger;
    }

    public async Task<IEnumerable<ApiEndpointConfig>> GetAllEndpointsAsync()
    {
        const string sql = @"
        SELECT Id, MethodName, HttpVerb, RouteTemplate, StoredProcedureName, 
               ParameterNames, IsActive, Description, RequiredRole
        FROM ApiEndpointConfig 
        WHERE IsActive = 1";

        try
        {
            using var connection = new SqlConnection(_connectionString);
            await connection.OpenAsync();
            return await connection.QueryAsync<ApiEndpointConfig>(sql);
        }
        catch (SqlException ex)
        {
            var csb = new SqlConnectionStringBuilder(_connectionString);
            _logger.LogError(ex, "Failed to connect to SQL Server {DataSource} as {UserId}. SqlException: {Message}",
                csb.DataSource, csb.UserID, ex.Message);
            throw;
        }
    }

    public async Task<ApiEndpointConfig?> GetEndpointByRouteAndVerbAsync(string routeTemplate, string httpVerb)
    {
        var endpoints = await GetCachedEndpointsInternalAsync();
        var key = BuildCacheKey(routeTemplate, httpVerb);
        return endpoints.TryGetValue(key, out var config) ? config : null;
    }

    public async Task ReloadCacheAsync()
    {
        _logger.LogInformation("Reloading API endpoint configuration cache...");
        
        _cache.Remove(CacheKey);
        await GetCachedEndpointsInternalAsync();
        
        _logger.LogInformation("API endpoint configuration cache reloaded successfully.");
    }

    public IReadOnlyDictionary<string, ApiEndpointConfig> GetCachedEndpoints()
    {
        if (_cache.TryGetValue(CacheKey, out Dictionary<string, ApiEndpointConfig>? endpoints) && endpoints != null)
        {
            return endpoints;
        }
        
        return new Dictionary<string, ApiEndpointConfig>().AsReadOnly();
    }

    private async Task<Dictionary<string, ApiEndpointConfig>> GetCachedEndpointsInternalAsync()
    {
        if (_cache.TryGetValue(CacheKey, out Dictionary<string, ApiEndpointConfig>? cached) && cached != null)
        {
            return cached;
        }

        _logger.LogInformation("Loading API endpoint configurations from database...");
        
        var endpoints = await GetAllEndpointsAsync();
        var endpointDict = new Dictionary<string, ApiEndpointConfig>(StringComparer.OrdinalIgnoreCase);

        foreach (var endpoint in endpoints)
        {
            var key = BuildCacheKey(endpoint.RouteTemplate, endpoint.HttpVerb);
            if (endpointDict.ContainsKey(key))
            {
                _logger.LogWarning("Duplicate endpoint configuration found: {Route} {Verb}", endpoint.RouteTemplate, endpoint.HttpVerb);
                continue;
            }
            endpointDict[key] = endpoint;
        }

        var cacheOptions = new MemoryCacheEntryOptions()
            .SetAbsoluteExpiration(CacheExpiration)
            .SetPriority(CacheItemPriority.High);

        _cache.Set(CacheKey, endpointDict, cacheOptions);
        
        _logger.LogInformation("Loaded {Count} active API endpoints into cache.", endpointDict.Count);
        
        return endpointDict;
    }

    private static string BuildCacheKey(string routeTemplate, string httpVerb)
    {
        return $"{httpVerb.ToUpperInvariant()}:{routeTemplate.ToLowerInvariant()}";
    }
}
