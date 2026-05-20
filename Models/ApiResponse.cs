namespace DyApi.Models;

public class ApiResponse<T>
{
    public bool Success { get; set; }
    public T? Data { get; set; }
    public string? Error { get; set; }

    public static ApiResponse<T> SuccessResponse(T data)
    {
        return new ApiResponse<T> { Success = true, Data = data };
    }

    public static ApiResponse<T> ErrorResponse(string error)
    {
        return new ApiResponse<T> { Success = false, Error = error };
    }
}

public class ApiResponse
{
    public bool Success { get; set; }
    public object? Data { get; set; }
    public string? Error { get; set; }

    public static ApiResponse SuccessResponse(object data)
    {
        return new ApiResponse { Success = true, Data = data };
    }

    public static ApiResponse ErrorResponse(string error)
    {
        return new ApiResponse { Success = false, Error = error };
    }
}
