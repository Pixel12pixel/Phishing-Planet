using MimeKit;

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
}