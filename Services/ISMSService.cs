namespace DyApi.Services;

public interface ISMSService
{
    Task<bool> SendSMSAsync(string phoneNumber, string message);
}
