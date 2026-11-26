using MimeKit;
using Phishing_Planet.Parsing.Models;

namespace Phishing_Planet.Parsing;

public interface IEmailParser
{
    Task<ParsedEmail> ParseAsync(MimeMessage message, CancellationToken cancellationToken = default);
}