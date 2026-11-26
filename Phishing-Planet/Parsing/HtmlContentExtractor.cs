using System.Text;
using MimeKit.Text;
using Phishing_Planet.Parsing.Models;

namespace Phishing_Planet.Parsing;

internal sealed record HtmlExtractionResult(string CleanText, IReadOnlyList<ExtractedLink> Links);

internal sealed class HtmlContentExtractor
{
    private static readonly HashSet<HtmlTagId> BlockTags =
    [
        HtmlTagId.Address, HtmlTagId.Article, HtmlTagId.Aside, HtmlTagId.BlockQuote,
        HtmlTagId.Br, HtmlTagId.Div, HtmlTagId.Footer, HtmlTagId.H1, HtmlTagId.H2,
        HtmlTagId.H3, HtmlTagId.H4, HtmlTagId.H5, HtmlTagId.H6, HtmlTagId.Header,
        HtmlTagId.HR, HtmlTagId.LI, HtmlTagId.Main, HtmlTagId.Nav, HtmlTagId.OL,
        HtmlTagId.P, HtmlTagId.Pre, HtmlTagId.Section, HtmlTagId.Table, HtmlTagId.TR,
        HtmlTagId.UL
    ];

    public HtmlExtractionResult Extract(string html)
    {
        if (string.IsNullOrWhiteSpace(html))
            return new HtmlExtractionResult(string.Empty, []);

        using var reader = new StringReader(html);
        var tokenizer = new HtmlTokenizer(reader)
        {
            DecodeCharacterReferences = true
        };

        var textBuilder = new StringBuilder(html.Length / 2);
        var links = new List<ExtractedLink>();

        var skipDepth = 0;
        string? href = null;
        var aTextBuilder = new StringBuilder();

        while (tokenizer.ReadNextToken(out var token))
        {
            switch (token)
            {
                case HtmlTagToken tag:
                    HandleTag(
                        tag,
                        textBuilder,
                        links,
                        ref skipDepth,
                        ref href,
                        aTextBuilder);
                    break;

                case HtmlDataToken data when skipDepth == 0:
                    textBuilder.Append(data.Data);
                    if (href is not null)
                        aTextBuilder.Append(data.Data);
                    break;
            }
        }

        if (href is not null)
        {
            TryAddLink(links, href, aTextBuilder.ToString(), LinkSource.HtmlAnchor);
        }

        return new HtmlExtractionResult(NormalizeWhitespace(textBuilder.ToString()), links);
    }

    private static void HandleTag(
        HtmlTagToken tag,
        StringBuilder textBuilder,
        List<ExtractedLink> links,
        ref int skipDepth,
        ref string? aHref,
        StringBuilder aTextBuilder)
    {
        if (IsSkippedContainer(tag))
        {
            if (tag.IsEndTag)
                skipDepth = Math.Max(0, skipDepth - 1);
            else if (!tag.IsEmptyElement)
                skipDepth++;

            return;
        }

        if (skipDepth > 0)
            return;

        if (BlockTags.Contains(tag.Id))
            textBuilder.Append('\n');
        else if (tag.Id is HtmlTagId.TD or HtmlTagId.TH && !tag.IsEndTag)
            textBuilder.Append(' ');

        switch (tag.Id)
        {
            case HtmlTagId.A when !tag.IsEndTag:
                var href = GetAttributeValue(tag, HtmlAttributeId.Href);
                if (!string.IsNullOrWhiteSpace(href))
                {
                    if (tag.IsEmptyElement)
                    {
                        TryAddLink(links, href, null, LinkSource.HtmlAnchor);
                    }
                    else
                    {
                        aHref = href;
                        aTextBuilder.Clear();
                    }
                }
                break;

            case HtmlTagId.A when tag.IsEndTag && aHref is not null:
                TryAddLink(links, aHref, aTextBuilder.ToString(), LinkSource.HtmlAnchor);
                aHref = null;
                aTextBuilder.Clear();
                break;

            case HtmlTagId.Form when !tag.IsEndTag:
                var action = GetAttributeValue(tag, HtmlAttributeId.Action);
                if (!string.IsNullOrWhiteSpace(action))
                    TryAddLink(links, action, null, LinkSource.HtmlForm);
                break;

            case HtmlTagId.Area when !tag.IsEndTag:
                var areaHref = GetAttributeValue(tag, HtmlAttributeId.Href);
                if (!string.IsNullOrWhiteSpace(areaHref))
                    TryAddLink(links, areaHref, GetAttributeValue(tag, HtmlAttributeId.Alt), LinkSource.HtmlArea);
                break;
        }
    }

    private static bool IsSkippedContainer(HtmlTagToken tag) =>
        tag.Id is HtmlTagId.Script or HtmlTagId.Style or HtmlTagId.Head or HtmlTagId.Title or HtmlTagId.NoScript
        || tag.Name.Equals("template", StringComparison.OrdinalIgnoreCase);

    private static string? GetAttributeValue(HtmlTagToken tag, HtmlAttributeId attributeId)
    {
        foreach (var attribute in tag.Attributes)
        {
            if (attribute.Id == attributeId)
                return attribute.Value;
        }

        return null;
    }

    private static void TryAddLink(
        List<ExtractedLink> links,
        string rawUrl,
        string? rawDisplayText,
        LinkSource source)
    {
        var link = CreateExtractedLink(rawUrl, rawDisplayText, source);
        if (link is not null)
            links.Add(link);
    }

    internal static ExtractedLink? CreateExtractedLink(
        string rawUrl,
        string? rawDisplayText,
        LinkSource source)
    {
        var trimmed = rawUrl.Trim();
        if (string.IsNullOrWhiteSpace(trimmed)
            || trimmed.StartsWith('#')
            || trimmed.StartsWith("cid:", StringComparison.OrdinalIgnoreCase)
            || trimmed.StartsWith("mailto:", StringComparison.OrdinalIgnoreCase)
            || trimmed.StartsWith("tel:", StringComparison.OrdinalIgnoreCase))
        {
            return null;
        }

        var displayText = string.IsNullOrWhiteSpace(rawDisplayText)
            ? null
            : NormalizeInlineWhitespace(rawDisplayText);

        var candidate = trimmed.StartsWith("//", StringComparison.Ordinal)
            ? $"https:{trimmed}"
            : trimmed;

        if (Uri.TryCreate(candidate, UriKind.Absolute, out var uri))
        {
            return new ExtractedLink(
                RawUrl: trimmed,
                NormalizedUrl: uri.AbsoluteUri,
                Scheme: uri.Scheme.ToLowerInvariant(),
                Host: string.IsNullOrEmpty(uri.Host) ? null : uri.Host.ToLowerInvariant(),
                DisplayText: displayText,
                Source: source);
        }

        var schemeEnd = trimmed.IndexOf(':');
        var scheme = schemeEnd > 0 ? trimmed[..schemeEnd].ToLowerInvariant() : null;
        if (scheme is "javascript" or "data" or "vbscript")
        {
            return new ExtractedLink(
                RawUrl: trimmed,
                NormalizedUrl: trimmed,
                Scheme: scheme,
                Host: null,
                DisplayText: displayText,
                Source: source);
        }

        return null;
    }

    internal static string NormalizeWhitespace(string input)
    {
        if (string.IsNullOrWhiteSpace(input))
            return string.Empty;

        var lines = input.Replace("\r\n", "\n").Replace('\r', '\n').Split('\n');
        var sb = new StringBuilder(input.Length);
        var blankLineCount = 0;

        foreach (var rawLine in lines)
        {
            var line = NormalizeInlineWhitespace(rawLine);
            if (line.Length == 0)
            {
                blankLineCount++;
                if (blankLineCount <= 1 && sb.Length > 0)
                    sb.Append('\n');
                continue;
            }

            blankLineCount = 0;
            if (sb.Length > 0)
                sb.Append('\n');
            sb.Append(line);
        }

        return sb.ToString().Trim();
    }

    private static string NormalizeInlineWhitespace(string text)
    {
        var sb = new StringBuilder(text.Length);
        var inWhitespace = false;

        foreach (var ch in text)
        {
            if (char.IsWhiteSpace(ch))
            {
                if (inWhitespace || sb.Length <= 0) continue;
                sb.Append(' ');
                inWhitespace = true;
            }
            else
            {
                sb.Append(ch);
                inWhitespace = false;
            }
        }

        return sb.ToString().TrimEnd();
    }
}