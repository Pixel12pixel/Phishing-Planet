namespace Phishing_Planet.Options;

public sealed class MailWatcherOptions
{
    public const string SectionName = "MailWatcher";

    public string Host { get; set; } = "localhost";
    public int Port { get; set; } = 143;
    public string Username { get; set; } = string.Empty;
    public string Password { get; set; } = string.Empty;
    public int PollIntervalSeconds { get; set; } = 5;
    public bool UseTls { get; set; }
}