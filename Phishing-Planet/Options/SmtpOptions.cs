namespace Phishing_Planet.Options;

public sealed class SmtpOptions
{
    public const string SectionName = "SmtpSender";

    public required string Host { get; set; }
    public required int Port { get; set; }
    public required string Username { get; set; }
    public required string Password { get; set; }
    public required string TargetEmail { get; set; }
}