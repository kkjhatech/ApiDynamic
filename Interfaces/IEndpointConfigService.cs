using DyApi.Models;

namespace DyApi.Interfaces;

public interface IEndpointConfigService
{
    Task<IEnumerable<ApiEndpointConfig>> GetAllEndpointsAsync();
    Task<ApiEndpointConfig?> GetEndpointByRouteAndVerbAsync(string routeTemplate, string httpVerb);
    Task ReloadCacheAsync();
    IReadOnlyDictionary<string, ApiEndpointConfig> GetCachedEndpoints();
}
