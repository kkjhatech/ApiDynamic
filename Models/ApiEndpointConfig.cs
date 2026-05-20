namespace DyApi.Models;

public class ApiEndpointConfig
{
    public int Id { get; set; }
    public string MethodName { get; set; } = string.Empty;
    public string HttpVerb { get; set; } = string.Empty;
    public string RouteTemplate { get; set; } = string.Empty;
    public string StoredProcedureName { get; set; } = string.Empty;
    public string ParameterNames { get; set; } = string.Empty;
    public bool IsActive { get; set; } = true;
    public string Description { get; set; } = string.Empty;
    public string? RequiredRole { get; set; }
    public int? ApplicationID { get; set; }
    public string APICall { get; set; } = "Normal"; // Normal, SMS, etc.

    public string[] GetParameterNames()
    {
        if (string.IsNullOrWhiteSpace(ParameterNames))
            return Array.Empty<string>();
        
        return ParameterNames.Split(',', StringSplitOptions.RemoveEmptyEntries)
                             .Select(p => p.Trim())
                             .ToArray();
    }
}
