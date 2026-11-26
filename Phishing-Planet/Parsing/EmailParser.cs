using System.Security.Cryptography;
using System.Text.RegularExpressions;
using MimeKit;
using Phishing_Planet.Parsing.Models;

namespace Phishing_Planet.Parsing;

public sealed partial class EmailParser : IEmailParser
{
    private const long MaxInMemoryAttachmentBytes = 10 * 1024 * 1024;

    private readonly HtmlContentExtractor _htmlExtractor;
    private readonly ForwardedEmailUnwrapper _unwrapper;

    public EmailParser()
    {
        _htmlExtractor = new HtmlContentExtractor();
        _unwrapper = new ForwardedEmailUnwrapper(_htmlExtractor);
    }

    [GeneratedRegex(@"\b(?:https?|ftp)://[^\s<>""'()\[\]{}]+", RegexOptions.IgnoreCase | RegexOptions.CultureInvariant)]
    private static partial Regex PlainTextUrlRegex();

    public async Task<ParsedEmail> ParseAsync(MimeMessage message, CancellationToken cancellationToken = default)
    {
        ArgumentNullException.ThrowIfNull(message);

        var unwrapped = _unwrapper.Unwrap(message);
        var target = unwrapped.TargetMessage;

        var metadata = ExtractMetadata(target, unwrapped.InlineHeaders);

        var rawHtmlBody = string.IsNullOrWhiteSpace(target.HtmlBody)
            ? null
            : target.HtmlBody;

        var htmlResult = unwrapped.PreExtractedHtml
            ?? (rawHtmlBody is not null
                ? _htmlExtractor.Extract(rawHtmlBody)
                : new HtmlExtractionResult(string.Empty, []));

        var cleanHtmlText = string.IsNullOrWhiteSpace(htmlResult.CleanText)
            ? null
            : htmlResult.CleanText;

        var rawPlainText = unwrapped.Mode == ForwardingMode.InlineBlock
            ? unwrapped.InlineBodyText
            : target.TextBody;

        var cleanPlainText = !string.IsNullOrWhiteSpace(rawPlainText)
            ? HtmlContentExtractor.NormalizeWhitespace(rawPlainText)
            : cleanHtmlText ?? string.Empty;

        var links = MergeAndDeduplicateLinks(htmlResult.Links, cleanPlainText);
        var attachments = await ExtractAttachmentsAsync(target, cancellationToken).ConfigureAwait(false);

        return new ParsedEmail(
            ForwardedBy: unwrapped.ForwardedBy,
            ForwardingMode: unwrapped.Mode,
            Metadata: metadata,
            PlainTextBody: cleanPlainText,
            RawHtmlBody: rawHtmlBody,
            CleanHtmlText: cleanHtmlText,
            Links: links,
            Attachments: attachments);
    }

    private static EmailMetadata ExtractMetadata(MimeMessage message, InlineForwardedHeaders? inlineHeaders)
    {
        var from = inlineHeaders?.From is { Count: > 0 }
            ? inlineHeaders.From
            : ToAddressList(message.From);

        var to = inlineHeaders?.To is { Count: > 0 }
            ? inlineHeaders.To
            : ToAddressList(message.To);

        var cc = inlineHeaders?.Cc is { Count: > 0 }
            ? inlineHeaders.Cc
            : ToAddressList(message.Cc);

        var replyTo = inlineHeaders?.ReplyTo is { Count: > 0 }
            ? inlineHeaders.ReplyTo
            : ToAddressList(message.ReplyTo);

        var subject = !string.IsNullOrWhiteSpace(inlineHeaders?.Subject)
            ? inlineHeaders.Subject
            : message.Subject ?? string.Empty;

        var date = inlineHeaders?.Date
            ?? (message.Date != DateTimeOffset.MinValue ? message.Date : null);

        var receivedHeaders = new List<string>();
        var authResults = new List<string>();
        var allHeaders = new Dictionary<string, List<string>>(StringComparer.OrdinalIgnoreCase);

        foreach (var header in message.Headers)
        {
            if (header.Id == HeaderId.Received)
                receivedHeaders.Add(header.Value);
            else if (header.Id == HeaderId.AuthenticationResults ||
                     header.Field.Equals("ARC-Authentication-Results", StringComparison.OrdinalIgnoreCase))
                authResults.Add(header.Value);

            if (!allHeaders.TryGetValue(header.Field, out var values))
            {
                values = [];
                allHeaders[header.Field] = values;
            }

            values.Add(header.Value);
        }

        var returnPath = message.Headers[HeaderId.ReturnPath]?.Trim();

        return new EmailMetadata(
            MessageId: message.MessageId,
            Subject: subject,
            Date: date,
            From: from,
            To: to,
            Cc: cc,
            ReplyTo: replyTo,
            ReturnPath: string.IsNullOrWhiteSpace(returnPath) ? null : returnPath,
            ReceivedHeaders: receivedHeaders,
            AuthenticationResults: authResults,
            AllHeaders: allHeaders.ToDictionary(
                kvp => kvp.Key, IReadOnlyList<string> (kvp) => kvp.Value,
                StringComparer.OrdinalIgnoreCase));
    }

    private static IReadOnlyList<EmailAddressInfo> ToAddressList(InternetAddressList addresses) =>
        addresses.Mailboxes
            .Select(m => new EmailAddressInfo(
                string.IsNullOrWhiteSpace(m.Name) ? null : m.Name,
                m.Address))
            .ToList();

    private static IReadOnlyList<ExtractedLink> MergeAndDeduplicateLinks(
        IReadOnlyList<ExtractedLink> htmlLinks,
        string plainTextBody)
    {
        var results = new List<ExtractedLink>(htmlLinks.Count);
        var seen = new HashSet<(string Url, string? DisplayText)>(
            EqualityComparer<(string, string?)>.Default);

        foreach (var link in htmlLinks)
        {
            var key = (link.NormalizedUrl.ToLowerInvariant(), link.DisplayText);
            if (seen.Add(key))
                results.Add(link);
        }

        if (string.IsNullOrWhiteSpace(plainTextBody))
            return results;

        var knownUrls = new HashSet<string>(
            results.Select(l => l.NormalizedUrl),
            StringComparer.OrdinalIgnoreCase);

        foreach (Match match in PlainTextUrlRegex().Matches(plainTextBody))
        {
            var raw = TrimTrailingPunctuation(match.Value);
            var link = HtmlContentExtractor.CreateExtractedLink(raw, null, LinkSource.PlainText);
            if (link is not null && knownUrls.Add(link.NormalizedUrl))
                results.Add(link);
        }

        return results;
    }

    private static string TrimTrailingPunctuation(string url) =>
        url.TrimEnd('.', ',', ';', ':', '!', '?', ')', ']', '}');

    private static async Task<IReadOnlyList<ParsedAttachment>> ExtractAttachmentsAsync(MimeMessage message, CancellationToken cancellationToken)
    {
        var attachments = new List<ParsedAttachment>();

        foreach (var entity in message.BodyParts)
        {
            if (entity is not MimePart part)
                continue;

            if (part is TextPart && !part.IsAttachment && string.IsNullOrWhiteSpace(part.FileName))
                continue;

            var fileName = part.FileName
                ?? part.ContentType.Name
                ?? $"unnamed.{GetFallbackExtension(part.ContentType.MimeType)}";

            var isInline = !part.IsAttachment &&
                string.Equals(
                    part.ContentDisposition?.Disposition,
                    ContentDisposition.Inline,
                    StringComparison.OrdinalIgnoreCase);

            var (sizeBytes, sha256Hash, bytes) = await HashAndBufferAsync(part, cancellationToken)
                .ConfigureAwait(false);

            attachments.Add(new ParsedAttachment(
                FileName: fileName,
                ContentType: part.ContentType.MimeType,
                ContentId: part.ContentId,
                IsInline: isInline,
                SizeBytes: sizeBytes,
                Sha256Hash: sha256Hash,
                Content: bytes));
        }

        return attachments;
    }

    private static async Task<(long SizeBytes, string Sha256Hash, ReadOnlyMemory<byte>? Content)> HashAndBufferAsync(MimePart part, CancellationToken cancellationToken)
    {
        await using var hashingStream = new HashingMemoryStream(MaxInMemoryAttachmentBytes);
        if (part.Content != null)
            await part.Content.DecodeToAsync(hashingStream, cancellationToken).ConfigureAwait(false);
        return hashingStream.Complete();
    }

    private static string GetFallbackExtension(string mimeType) =>
        mimeType.ToLowerInvariant() switch
        {
            "image/png" => "png",
            "image/jpeg" => "jpg",
            "image/gif" => "gif",
            "application/pdf" => "pdf",
            _ => "bin"
        };
    
    private sealed class HashingMemoryStream(long maxBufferBytes) : Stream
    {
        private readonly IncrementalHash _hash = IncrementalHash.CreateHash(HashAlgorithmName.SHA256);
        private MemoryStream? _buffer = new();
        private long _totalBytes;

        public override bool CanRead => false;
        public override bool CanSeek => false;
        public override bool CanWrite => true;
        public override long Length => _totalBytes;
        public override long Position
        {
            get => _totalBytes;
            set => throw new NotSupportedException();
        }

        public override void Write(byte[] buffer, int offset, int count) =>
            Write(buffer.AsSpan(offset, count));

        public override void Write(ReadOnlySpan<byte> buffer)
        {
            if (buffer.IsEmpty)
                return;

            _hash.AppendData(buffer);
            _totalBytes += buffer.Length;

            if (_buffer is null)
                return;

            if (_totalBytes <= maxBufferBytes)
            {
                _buffer.Write(buffer);
            }
            else
            {
                _buffer.Dispose();
                _buffer = null;
            }
        }

        public override ValueTask WriteAsync(ReadOnlyMemory<byte> buffer, CancellationToken cancellationToken = default)
        {
            cancellationToken.ThrowIfCancellationRequested();
            Write(buffer.Span);
            return ValueTask.CompletedTask;
        }

        public override Task WriteAsync(
            byte[] buffer,
            int offset,
            int count,
            CancellationToken cancellationToken)
        {
            cancellationToken.ThrowIfCancellationRequested();
            Write(buffer.AsSpan(offset, count));
            return Task.CompletedTask;
        }

        public (long SizeBytes, string Sha256Hash, ReadOnlyMemory<byte>? Content) Complete()
        {
            var hashHex = Convert.ToHexStringLower(_hash.GetCurrentHash());
            ReadOnlyMemory<byte>? content = _buffer?.ToArray();

            return (_totalBytes, hashHex, content);
        }

        public override void Flush() { }
        public override int Read(byte[] buffer, int offset, int count) => throw new NotSupportedException();
        public override long Seek(long offset, SeekOrigin origin) => throw new NotSupportedException();
        public override void SetLength(long value) => throw new NotSupportedException();

        protected override void Dispose(bool disposing)
        {
            if (disposing)
            {
                _hash.Dispose();
                _buffer?.Dispose();
            }

            base.Dispose(disposing);
        }
    }
}