using Dapper;
using System.Data.SqlClient;
using System.Data;

namespace DyApi.Services;

public interface IDynamicQueryService
{
    Task<IEnumerable<dynamic>> ExecuteStoredProcedureAsync(string spName, Dictionary<string, object?> parameters);
}

public class DynamicQueryService : IDynamicQueryService
{
    private readonly string _connectionString;
    private readonly ILogger<DynamicQueryService> _logger;

    public DynamicQueryService(IConfiguration configuration, ILogger<DynamicQueryService> logger)
    {
        _connectionString = configuration.GetConnectionString("DefaultConnection") 
            ?? throw new InvalidOperationException("DefaultConnection connection string not found.");
        _logger = logger;
    }

    public async Task<IEnumerable<dynamic>> ExecuteStoredProcedureAsync(
        string spName, 
        Dictionary<string, object?> parameters)
    {
        _logger.LogInformation("Executing stored procedure: {StoredProcedure}", spName);
        
        using var connection = new SqlConnection(_connectionString);
        await connection.OpenAsync();

        var dynamicParams = new DynamicParameters();
        
        foreach (var param in parameters)
        {
            var value = param.Value ?? DBNull.Value;
            dynamicParams.Add(param.Key, value);
            
            _logger.LogDebug("Parameter: {Name} = {Value}", param.Key, 
                IsSensitiveParameter(param.Key) ? "***" : value);
        }

        try
        {
            var result = await connection.QueryAsync(spName, dynamicParams, commandType: CommandType.StoredProcedure);
            
            _logger.LogInformation("Stored procedure {StoredProcedure} executed successfully. Rows returned: {RowCount}", 
                spName, result.Count());
            
            return result;
        }
        catch (SqlException ex)
        {
            _logger.LogError(ex, "SQL error executing stored procedure {StoredProcedure}: {ErrorMessage}", 
                spName, ex.Message);
            throw;
        }
        catch (Exception ex)
        {
            _logger.LogError(ex, "Error executing stored procedure {StoredProcedure}: {ErrorMessage}", 
                spName, ex.Message);
            throw;
        }
    }

    private static bool IsSensitiveParameter(string paramName)
    {
        var sensitiveKeywords = new[] { "password", "secret", "token", "key", "credential", "auth" };
        return sensitiveKeywords.Any(keyword => 
            paramName.Contains(keyword, StringComparison.OrdinalIgnoreCase));
    }
}
