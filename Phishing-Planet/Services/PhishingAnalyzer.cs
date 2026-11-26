
using Microsoft.Extensions.Options;
using MimeKit;
using Phishing_Planet.Options;

namespace Phishing_Planet.Services;

public class PhishingAnalyzer(
    IOptions<PhishingSettings> settings) : IPhishingAnalyzer
{
    private readonly PhishingSettings _settings = settings.Value;

    public int Analyze(MimeMessage message)
    {
        var score = 0;

        var sender = message.From.Mailboxes.FirstOrDefault();

        var content =
            $"{message.Subject} {message.TextBody} {message.HtmlBody}";


        foreach (var word in PhishingRules.SuspiciousWords)
        {
            if (content.Contains(
                word,
                StringComparison.OrdinalIgnoreCase))
            {
                score += _settings.SuspiciousPhraseScore;
            }
        }


        if (sender != null)
        {
            var domain = PhishingRules.GetDomain(sender.Address);

            foreach (var brand in PhishingRules.TrustedBrands)
            {
                if (sender.Name.Contains(
                        brand,
                        StringComparison.OrdinalIgnoreCase) &&
                    !IsOfficialDomain(domain, brand))
                {
                    score += _settings.SuspiciousSenderScore;
                    break;
                }
            }
        }


        foreach (var attachment in message.Attachments)
        {
            var filename =
                attachment.ContentDisposition?.FileName ??
                attachment.ContentType.Name ??
                "";

            var extension = Path.GetExtension(filename);


            if (PhishingRules.DangerousExtensions.Contains(
                extension,
                StringComparer.OrdinalIgnoreCase))
            {
                score += _settings.DangerousExtensionScore;


                var previousExtension = Path.GetExtension(
                    Path.GetFileNameWithoutExtension(filename));

                if (!string.IsNullOrEmpty(previousExtension))
                {
                    score += _settings.DoubleExtensionScore;
                }
            }


            var mimeType = attachment.ContentType.MimeType;

            if (PhishingRules.DangerousMimeTypes.Contains(
                mimeType,
                StringComparer.OrdinalIgnoreCase))
            {
                score += _settings.DangerousMimeScore;
            }
        }


        var urls = PhishingRules.UrlRegex.Matches(content)
            .Select(x => x.Value.TrimEnd('.', ',', ';', ')', ']'))
            .Distinct(StringComparer.OrdinalIgnoreCase);

        foreach (var url in urls)
        {
            if (!Uri.TryCreate(url, UriKind.Absolute, out var uri))
                continue;

            var host = uri.IdnHost.ToLowerInvariant();


            if (PhishingRules.IsIpAddress(host))
            {
                score += _settings.IpUrlScore;
            }


            if (PhishingRules.IsHomoglyphDomain(host))
            {
                score += _settings.HomoglyphScore;
            }


            if (PhishingRules.IsTyposquatting(host))
            {
                score += _settings.TyposquattingScore;
            }


            if (PhishingRules.HasExcessiveSubdomains(host))
            {
                score += _settings.ExcessiveSubdomainsScore;
            }


            if (PhishingRules.UrlShorteners.Contains(host))
            {
                score += _settings.UrlShortenerScore;
            }
        }

        return Math.Clamp(score, 0, _settings.MaxScore);
    }

    private static bool IsOfficialDomain(
        string domain,
        string brand)
    {
        var officialDomain = $"{brand}.com";

        return domain.Equals(
                   officialDomain,
                   StringComparison.OrdinalIgnoreCase)
               ||
               domain.EndsWith(
                   "." + officialDomain,
                   StringComparison.OrdinalIgnoreCase);
    }
}