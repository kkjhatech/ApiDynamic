namespace DyApi.Interfaces;

public interface IDynamicQueryService
{
    Task<IEnumerable<dynamic>> ExecuteStoredProcedureAsync(string spName, Dictionary<string, object?> parameters);
}
