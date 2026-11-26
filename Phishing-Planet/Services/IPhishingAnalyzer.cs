
using MimeKit;

namespace Phishing_Planet.Services;

public interface IPhishingAnalyzer
{
    int Analyze(MimeMessage message);
}