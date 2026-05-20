namespace DyApi.Services;

public class SMSService : ISMSService
{
    private readonly ILogger<SMSService> _logger;

    public SMSService(ILogger<SMSService> logger)
    {
        _logger = logger;
    }

    public Task<bool> SendSMSAsync(string phoneNumber, string message)
    {
        // Mock implementation - logs SMS instead of sending
        // In production, integrate with Twilio, AWS SNS, or other SMS provider
        _logger.LogInformation("SMS sent to {PhoneNumber}: {Message}", phoneNumber, message);
        return Task.FromResult(true);
    }
}
