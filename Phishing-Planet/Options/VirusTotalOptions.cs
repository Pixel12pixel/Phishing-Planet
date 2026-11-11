namespace Phishing_Planet.Options;

public sealed class VirusTotalOptions
{
    public const string SectionName = "VirusTotal";
    public string ApiKey { get; set; } = string.Empty;
    public string BaseUrl { get; set; } = "https://www.virustotal.com/api/v3/";
    public int RequestsPerMinute { get; set; } = 4;
    public int RequestsPerDay { get; set; } = 500;
    public int RequestsPerMonth { get; set; } = 15_500;
    public bool RunDemoOnStartup { get; set; }
}