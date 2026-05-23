namespace DyApi.Interfaces;

public interface ISMSService
{
    Task<bool> SendSMSAsync(string phoneNumber, string message);
}
