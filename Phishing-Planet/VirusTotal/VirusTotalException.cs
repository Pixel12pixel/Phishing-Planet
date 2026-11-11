using System.Net;
using System.Net.Http.Headers;
using System.Text.Json;

namespace Phishing_Planet.VirusTotal;

public sealed class VirusTotalException(
    HttpStatusCode statusCode,
    string? errorCode,
    string message,
    TimeSpan? retryAfter = null,
    Exception? innerException = null)
    : Exception(message, innerException)
{
    public HttpStatusCode StatusCode { get; } = statusCode;

    public string? ErrorCode { get; } = errorCode;

    public TimeSpan? RetryAfter { get; } = retryAfter;

    public static VirusTotalException Create(
        HttpStatusCode statusCode,
        string responseBody,
        RetryConditionHeaderValue? retryAfter)
    {
        string? errorCode = null;
        var message = $"VirusTotal API returned {(int)statusCode} ({statusCode}).";

        if (!string.IsNullOrWhiteSpace(responseBody))
        {
            try
            {
                using var document = JsonDocument.Parse(responseBody);

                if (document.RootElement.TryGetProperty("error", out var error))
                {
                    if (error.TryGetProperty("code", out var code))
                        errorCode = code.GetString();

                    if (error.TryGetProperty("message", out var errorMessage))
                        message = errorMessage.GetString() ?? message;
                }
            }
            catch (JsonException)
            {
            }
        }

        var delay = retryAfter?.Delta;

        if (delay is null && retryAfter?.Date is { } retryDate)
            delay = retryDate - DateTimeOffset.UtcNow;

        return new VirusTotalException(statusCode, errorCode, message, delay);
    }
}