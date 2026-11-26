using System.Text.RegularExpressions;
using MimeKit;
using MimeKit.Utils;
using Phishing_Planet.Parsing.Models;

namespace Phishing_Planet.Parsing;

internal sealed record InlineForwardedHeaders(
    IReadOnlyList<EmailAddressInfo> From,
    IReadOnlyList<EmailAddressInfo> To,
    IReadOnlyList<EmailAddressInfo> Cc,
    IReadOnlyList<EmailAddressInfo> ReplyTo,
    string? Subject,
    DateTimeOffset? Date);

internal sealed record UnwrapResult(
    MimeMessage TargetMessage,
    EmailAddressInfo? ForwardedBy,
    ForwardingMode Mode,
    InlineForwardedHeaders? InlineHeaders,
    string? InlineBodyText,
    HtmlExtractionResult? PreExtractedHtml);

internal sealed partial class ForwardedEmailUnwrapper(HtmlContentExtractor htmlExtractor)
{
    private const int MaxUnwrapDepth = 5;

    [GeneratedRegex(@"^[\-\s_]*(?:Forwarded message|Original Message|Begin forwarded message|Przekazana wiadomość|Wiadomość oryginalna)[\-\s_:]*$", 
        RegexOptions.IgnoreCase | RegexOptions.Multiline | RegexOptions.CultureInvariant)]
    private static partial Regex ForwardMarkerRegex();

    [GeneratedRegex(@"^(?<key>From|Od|To|Do|Cc|DW|Reply-To|Odpowiedz do|Subject|Temat|Date|Sent|Data|Wysłano)\s*:\s*(?<value>.+)$",
        RegexOptions.IgnoreCase | RegexOptions.CultureInvariant)]
    private static partial Regex InlineHeaderLineRegex();

    public UnwrapResult Unwrap(MimeMessage outerMessage)
    {
        var outerSender = outerMessage.From.Mailboxes
            .Select(m => new EmailAddressInfo(
                string.IsNullOrWhiteSpace(m.Name) ? null : m.Name,
                m.Address))
            .FirstOrDefault();

        var current = outerMessage;
        var unwrappedEml = false;

        for (var depth = 0; depth < MaxUnwrapDepth; depth++)
        {
            var embedded = FindEmbeddedRfc822Message(current);
            if (embedded is null)
                break;

            current = embedded;
            unwrappedEml = true;
        }

        if (unwrappedEml)
        {
            return new UnwrapResult(
                TargetMessage: current,
                ForwardedBy: outerSender,
                Mode: ForwardingMode.Rfc822Attachment,
                InlineHeaders: null,
                InlineBodyText: null,
                PreExtractedHtml: null);
        }

        var textBody = outerMessage.TextBody;
        if (!string.IsNullOrWhiteSpace(textBody) &&
            TryParseInlineForward(textBody, out var inlineHeaders, out var inlineBody))
        {
            return new UnwrapResult(
                TargetMessage: outerMessage,
                ForwardedBy: outerSender,
                Mode: ForwardingMode.InlineBlock,
                InlineHeaders: inlineHeaders,
                InlineBodyText: inlineBody,
                PreExtractedHtml: null);
        }

        if (string.IsNullOrWhiteSpace(outerMessage.HtmlBody))
            return new UnwrapResult(
                TargetMessage: outerMessage,
                ForwardedBy: null,
                Mode: ForwardingMode.None,
                InlineHeaders: null,
                InlineBodyText: null,
                PreExtractedHtml: null);
        var htmlResult = htmlExtractor.Extract(outerMessage.HtmlBody);
        if (!string.IsNullOrWhiteSpace(htmlResult.CleanText) &&
            TryParseInlineForward(htmlResult.CleanText, out var htmlInlineHeaders, out var htmlInlineBody))
        {
            return new UnwrapResult(
                TargetMessage: outerMessage,
                ForwardedBy: outerSender,
                Mode: ForwardingMode.InlineBlock,
                InlineHeaders: htmlInlineHeaders,
                InlineBodyText: htmlInlineBody,
                PreExtractedHtml: htmlResult);
        }

        return new UnwrapResult(
            TargetMessage: outerMessage,
            ForwardedBy: null,
            Mode: ForwardingMode.None,
            InlineHeaders: null,
            InlineBodyText: null,
            PreExtractedHtml: htmlResult);

    }

    private static MimeMessage? FindEmbeddedRfc822Message(MimeMessage message)
    {
        foreach (var part in message.BodyParts)
        {
            if (part is MessagePart { Message: not null } messagePart)
                return messagePart.Message;
        }

        return null;
    }

    private static bool TryParseInlineForward(
        string textBody,
        out InlineForwardedHeaders? headers,
        out string? forwardedBody)
    {
        headers = null;
        forwardedBody = null;

        var normalized = textBody.Replace("\r\n", "\n").Replace('\r', '\n');
        var match = ForwardMarkerRegex().Match(normalized);
        if (!match.Success)
            return false;

        var afterMarker = normalized[(match.Index + match.Length)..];
        var lines = afterMarker.Split('\n');

        var from = new List<EmailAddressInfo>();
        var to = new List<EmailAddressInfo>();
        var cc = new List<EmailAddressInfo>();
        var replyTo = new List<EmailAddressInfo>();
        string? subject = null;
        DateTimeOffset? date = null;

        var headerCount = 0;
        var bodyStartLine = 0;

        for (var i = 0; i < lines.Length; i++)
        {
            var line = lines[i].Trim();

            if (line.Length == 0)
            {
                if (headerCount > 0)
                {
                    bodyStartLine = i + 1;
                    break;
                }

                continue;
            }

            var headerMatch = InlineHeaderLineRegex().Match(line);
            if (!headerMatch.Success)
            {
                bodyStartLine = i;
                break;
            }

            headerCount++;
            var key = headerMatch.Groups["key"].Value.ToLowerInvariant();
            var value = headerMatch.Groups["value"].Value.Trim();

            switch (key)
            {
                case "from" or "od":
                    ParseAddresses(value, from);
                    break;
                case "to" or "do":
                    ParseAddresses(value, to);
                    break;
                case "cc" or "dw":
                    ParseAddresses(value, cc);
                    break;
                case "reply-to" or "odpowiedz do":
                    ParseAddresses(value, replyTo);
                    break;
                case "subject" or "temat":
                    subject = value;
                    break;
                case "date" or "sent" or "data" or "wysłano":
                    if (DateUtils.TryParse(value, out var rfcDate))
                        date = rfcDate;
                    else if (DateTimeOffset.TryParse(value, out var parsedDate))
                        date = parsedDate;
                    break;
            }

            bodyStartLine = i + 1;
        }

        if (headerCount == 0)
            return false;

        headers = new InlineForwardedHeaders(from, to, cc, replyTo, subject, date);
        forwardedBody = string.Join('\n', lines[bodyStartLine..]).Trim();
        return true;
    }

    private static void ParseAddresses(string raw, List<EmailAddressInfo> target)
    {
        if (InternetAddressList.TryParse(raw, out var list))
        {
            foreach (var mailbox in list.Mailboxes)
            {
                target.Add(new EmailAddressInfo(
                    string.IsNullOrWhiteSpace(mailbox.Name) ? null : mailbox.Name,
                    mailbox.Address));
            }

            return;
        }

        if (!string.IsNullOrWhiteSpace(raw))
            target.Add(new EmailAddressInfo(null, raw));
    }
}