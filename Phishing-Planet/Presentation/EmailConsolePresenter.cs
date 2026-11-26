using MimeKit;
using Phishing_Planet.Parsing.Models;

namespace Phishing_Planet.Presentation;

public sealed class EmailConsolePresenter : IEmailPresenter
{
    private const int BodyPreviewLength = 500;

    public void ShowInfo(string message) => Console.WriteLine(message);

    public void ShowError(Exception exception) =>
        Console.WriteLine($"[error] {exception.GetType().Name}: {exception.Message}");

    public void ShowEmail(MimeMessage message)
    {
        Console.WriteLine();
        Console.WriteLine("═══════════════════════════════════════════════");
        Console.WriteLine($"From:    {message.From}");
        Console.WriteLine($"To:      {message.To}");
        Console.WriteLine($"Subject: {message.Subject}");
        Console.WriteLine($"Date:    {message.Date.LocalDateTime:yyyy-MM-dd HH:mm:ss}");
        Console.WriteLine("───────────────────────────────────────────────");

        var body = (message.TextBody ?? message.HtmlBody ?? "(empty body)").Trim();
        Console.WriteLine(body.Length > BodyPreviewLength
            ? string.Concat(body.AsSpan(0, BodyPreviewLength), "\n…(truncated)")
            : body);

        Console.WriteLine("═══════════════════════════════════════════════");
    }
    
    public void ShowParsedEmail(ParsedEmail email)
{
    Console.WriteLine();
    Console.WriteLine("═══════════════════════════════════════════════");
    if (email.WasForwarded)
        Console.WriteLine($"Forwarded:   {email.ForwardingMode} by {email.ForwardedBy?.Address ?? "(unknown)"}");

    Console.WriteLine($"From:        {FormatAddresses(email.Metadata.From)}");
    Console.WriteLine($"To:          {FormatAddresses(email.Metadata.To)}");
    Console.WriteLine($"Reply-To:    {FormatAddresses(email.Metadata.ReplyTo)}");
    Console.WriteLine($"Return-Path: {email.Metadata.ReturnPath ?? "(none)"}");
    Console.WriteLine($"Subject:     {email.Metadata.Subject}");
    Console.WriteLine($"Date:        {(email.Metadata.Date is { } d ? d.LocalDateTime.ToString("yyyy-MM-dd HH:mm:ss") : "(none)")}");
    Console.WriteLine($"Received:    {email.Metadata.ReceivedHeaders.Count} hop(s)");
    Console.WriteLine($"Auth-Res:    {(email.Metadata.AuthenticationResults.Count > 0 ? string.Join(" | ", email.Metadata.AuthenticationResults) : "(none)")}");
    Console.WriteLine($"Links:       {email.Links.Count}");
    foreach (var link in email.Links)
    {
        Console.WriteLine($"  - [{link.Source}] {link.NormalizedUrl}" +
            (link.DisplayText is not null ? $" (text: \"{link.DisplayText}\")" : string.Empty));
    }

    Console.WriteLine($"Attachments: {email.Attachments.Count}");
    foreach (var att in email.Attachments)
        Console.WriteLine($"  - {att.FileName} ({att.ContentType}, {att.SizeBytes} B, SHA-256: {att.Sha256Hash})");

    Console.WriteLine("───────────────────────────────────────────────");
    var body = string.IsNullOrWhiteSpace(email.PlainTextBody) ? "(empty body)" : email.PlainTextBody;
    Console.WriteLine(body.Length > BodyPreviewLength
        ? string.Concat(body.AsSpan(0, BodyPreviewLength), "\n…(truncated)")
        : body);
    Console.WriteLine("═══════════════════════════════════════════════");
}

private static string FormatAddresses(IReadOnlyList<EmailAddressInfo> addresses) =>
    addresses.Count == 0
        ? "(none)"
        : string.Join(", ", addresses.Select(a =>
            string.IsNullOrWhiteSpace(a.DisplayName)
                ? a.Address
                : $"{a.DisplayName} <{a.Address}>"));
}