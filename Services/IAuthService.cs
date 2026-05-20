using DyApi.Models;

namespace DyApi.Services;

public interface IAuthService
{
    Task<LoginResponse?> LoginAsync(LoginRequest request);
    Task<bool> LogoutAsync(string refreshToken);
    Task<bool> RegisterAsync(User user, string password);
    Task<bool> ValidateCredentialsAsync(string username, string password);
}
