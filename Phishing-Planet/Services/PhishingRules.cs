using System.Net;
using System.Text.RegularExpressions;

namespace Phishing_Planet.Services;

public class PhishingRules
{
    public static readonly string[] SuspiciousWords =
    [
        "pilnie",
        "natychmiast",
        "konto zostanie zablokowane",
        "ostatnie ostrzeżenie",
        "zweryfikuj swoje konto",
        "podaj hasło",
        "weryfikacja wymagana",
        "urgent",
        "immediately",
        "account suspended",
        "verify your account",
        "confirm your password"
    ];

    public static readonly string[] TrustedBrands =
    [
        "paypal",
        "microsoft",
        "google",
        "amazon",
        "apple",
        "netflix"
    ];

    public static readonly string[] DangerousExtensions =
    [
        ".exe", ".scr", ".bat", ".cmd",
        ".ps1", ".vbs", ".js", ".jse",
        ".msi", ".hta", ".iso", ".img",
        ".lnk", ".reg", ".com", ".wsf"
    ];

    public static readonly string[] DangerousMimeTypes =
    [
        "application/x-msdownload",
        "application/x-dosexec",
        "application/x-executable",
        "application/vnd.microsoft.portable-executable",
        "application/x-msi",
        "application/x-sh",
        "application/x-bat",
        "application/x-powershell",
        "application/x-elf"
    ];

    public static readonly string[] UrlShorteners =
    [
        "bit.ly",
        "tinyurl.com",
        "t.co",
        "is.gd",
        "cutt.ly",
        "rb.gy",
        "rebrand.ly",
        "shorturl.at",
        "ow.ly",
        "buff.ly"
    ];

    public static readonly Regex UrlRegex = new(
        @"https?://[^\s<>""']+",
        RegexOptions.IgnoreCase | RegexOptions.Compiled);

    public static bool IsIpAddress(string host)
    {
        return IPAddress.TryParse(host, out _);
    }

    public static bool IsHomoglyphDomain(string host)
    {
        if (host.Any(c => c > 127))
            return true;
        
        if (host.Contains("xn--", StringComparison.OrdinalIgnoreCase))
            return true;

        return false;
    }

    public static bool HasExcessiveSubdomains(string host)
    {
        var labels = host.Split(
            '.',
            StringSplitOptions.RemoveEmptyEntries);
        

        return labels.Length > 3;
    }

    public static bool IsTyposquatting(string host)
    {
        var labels = host
            .ToLowerInvariant()
            .Split('.');

        foreach (var label in labels)
        {
            foreach (var brand in TrustedBrands)
            {
                if (label == brand)
                    continue;
                
                if (LevenshteinDistance(label, brand) <= 1)
                    return true;
            }
        }

        return false;
    }

    public static int LevenshteinDistance(string a, string b)
    {
        var matrix = new int[a.Length + 1, b.Length + 1];

        for (var i = 0; i <= a.Length; i++)
            matrix[i, 0] = i;

        for (var j = 0; j <= b.Length; j++)
            matrix[0, j] = j;

        for (var i = 1; i <= a.Length; i++)
        {
            for (var j = 1; j <= b.Length; j++)
            {
                var cost = a[i - 1] == b[j - 1] ? 0 : 1;

                matrix[i, j] = Math.Min(
                    Math.Min(
                        matrix[i - 1, j] + 1,
                        matrix[i, j - 1] + 1),
                    matrix[i - 1, j - 1] + cost);
            }
        }

        return matrix[a.Length, b.Length];
    }

    public static string GetDomain(string email)
    {
        var index = email.LastIndexOf('@');

        return index >= 0
            ? email[(index + 1)..].TrimEnd('.')
            : "";
    }
}