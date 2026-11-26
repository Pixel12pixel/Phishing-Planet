
namespace Phishing_Planet.Options;

public class PhishingSettings
{
    public int MaxScore { get; set; } = 100;

    public int SuspiciousPhraseScore { get; set; } = 10;
    public int SuspiciousSenderScore { get; set; } = 20;

    public int DangerousExtensionScore { get; set; } = 30;
    public int DoubleExtensionScore { get; set; } = 25;
    public int DangerousMimeScore { get; set; } = 30;

    public int IpUrlScore { get; set; } = 25;
    public int HomoglyphScore { get; set; } = 25;
    public int TyposquattingScore { get; set; } = 25;
    public int ExcessiveSubdomainsScore { get; set; } = 15;
    public int UrlShortenerScore { get; set; } = 15;
}