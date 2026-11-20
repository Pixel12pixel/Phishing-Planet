using MimeKit;

namespace Phishing_Planet.Services;

public interface IMailSenderService
{
    Task SendEmailAsync(
        string recipientAddress,
        string subject,
        string plainTextBody,
        string? htmlBody = null,
        string? inReplyToMessageId = null,
        CancellationToken cancellationToken = default);
    
    Task SendReplyReportAsync(
        MimeMessage originalMessage,
        string plainTextReport,
        string? htmlReport = null,
        CancellationToken cancellationToken = default);
}