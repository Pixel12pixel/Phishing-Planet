namespace Phishing_Planet.Parsing.Models;

public enum ForwardingMode
{
    None,
    Rfc822Attachment,
    InlineBlock
}

public enum LinkSource
{
    PlainText,
    HtmlAnchor,
    HtmlForm,
    HtmlArea
}

public sealed record EmailAddressInfo(
    string? DisplayName,
    string Address);

public sealed record EmailMetadata(
    string? MessageId,
    string Subject,
    DateTimeOffset? Date,
    IReadOnlyList<EmailAddressInfo> From,
    IReadOnlyList<EmailAddressInfo> To,
    IReadOnlyList<EmailAddressInfo> Cc,
    IReadOnlyList<EmailAddressInfo> ReplyTo,
    string? ReturnPath,
    IReadOnlyList<string> ReceivedHeaders,
    IReadOnlyList<string> AuthenticationResults,
    IReadOnlyDictionary<string, IReadOnlyList<string>> AllHeaders);

public sealed record ExtractedLink(
    string RawUrl,
    string NormalizedUrl,
    string? Scheme,
    string? Host,
    string? DisplayText,
    LinkSource Source);

public sealed record ParsedAttachment(
    string FileName,
    string ContentType,
    string? ContentId,
    bool IsInline,
    long SizeBytes,
    string Sha256Hash,
    ReadOnlyMemory<byte>? Content);

public sealed record ParsedEmail(
    EmailAddressInfo? ForwardedBy,
    ForwardingMode ForwardingMode,
    EmailMetadata Metadata,
    string PlainTextBody,
    string? RawHtmlBody,
    string? CleanHtmlText,
    IReadOnlyList<ExtractedLink> Links,
    IReadOnlyList<ParsedAttachment> Attachments)
{
    public bool WasForwarded => ForwardingMode != ForwardingMode.None;
}