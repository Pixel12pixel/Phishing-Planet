using MailKit.Net.Smtp;
using MailKit.Security;
using Microsoft.Extensions.Logging;
using Microsoft.Extensions.Options;
using MimeKit;
using Phishing_Planet.Options;

namespace Phishing_Planet.Services;

public sealed class MailSenderService(
    IOptions<SmtpOptions> options,
    ILogger<MailSenderService> logger)
    : IMailSenderService
{
    private readonly SmtpOptions _options = options.Value;

    public async Task SendEmailAsync(
        string recipientAddress,
        string subject,
        string plainTextBody,
        string? htmlBody = null,
        string? inReplyToMessageId = null,
        CancellationToken cancellationToken = default)
    {
        ArgumentException.ThrowIfNullOrWhiteSpace(recipientAddress);
        ArgumentException.ThrowIfNullOrWhiteSpace(subject);
        ArgumentException.ThrowIfNullOrWhiteSpace(plainTextBody);

        var message = new MimeMessage();
        message.From.Add(new MailboxAddress(_options.SenderName, _options.Username));
        message.To.Add(MailboxAddress.Parse(recipientAddress));
        message.Subject = subject;

        if (!string.IsNullOrWhiteSpace(inReplyToMessageId))
        {
            message.InReplyTo = inReplyToMessageId;
            message.References.Add(inReplyToMessageId);
        }

        var bodyBuilder = new BodyBuilder
        {
            TextBody = plainTextBody,
            HtmlBody = htmlBody
        };
        message.Body = bodyBuilder.ToMessageBody();

        var secureOption = _options.UseTls
            ? SecureSocketOptions.StartTlsWhenAvailable
            : SecureSocketOptions.None;

        using var smtpClient = new SmtpClient();

        await smtpClient.ConnectAsync(_options.Host, _options.Port, secureOption, cancellationToken);

        if (!string.IsNullOrWhiteSpace(_options.Username))
        {
            await smtpClient.AuthenticateAsync(_options.Username, _options.Password, cancellationToken);
        }

        await smtpClient.SendAsync(message, cancellationToken);
        await smtpClient.DisconnectAsync(quit: true, cancellationToken);

        logger.LogInformation("Analysis report sent successfully via SMTP.");
    }

    public async Task SendReplyReportAsync(
        MimeMessage originalMessage,
        string plainTextReport,
        string? htmlReport = null,
        CancellationToken cancellationToken = default)
    {
        ArgumentNullException.ThrowIfNull(originalMessage);

        var recipient = ResolveReplyRecipient(originalMessage);
        if (recipient is null)
        {
            logger.LogWarning("Could not resolve a valid reply recipient for message {MessageId}.", originalMessage.MessageId);
            return;
        }

        var originalSubject = string.IsNullOrWhiteSpace(originalMessage.Subject)
            ? "(No Subject)"
            : originalMessage.Subject;

        var replySubject = originalSubject.StartsWith("Re:", StringComparison.OrdinalIgnoreCase)
            ? $"[Phishing-Planet Report] {originalSubject}"
            : $"Re: [Phishing-Planet Report] {originalSubject}";

        await SendEmailAsync(
            recipientAddress: recipient.Address,
            subject: replySubject,
            plainTextBody: plainTextReport,
            htmlBody: htmlReport,
            inReplyToMessageId: originalMessage.MessageId,
            cancellationToken: cancellationToken);
    }

    private MailboxAddress? ResolveReplyRecipient(MimeMessage message)
    {
        var sender = message.ReplyTo.Mailboxes.FirstOrDefault()
                     ?? message.From.Mailboxes.FirstOrDefault();

        if (sender is not null)
            return sender;
        
        if (!string.IsNullOrWhiteSpace(_options.TargetEmail) &&
            MailboxAddress.TryParse(_options.TargetEmail, out var fallback))
        {
            return fallback;
        }

        return null;
    }
}