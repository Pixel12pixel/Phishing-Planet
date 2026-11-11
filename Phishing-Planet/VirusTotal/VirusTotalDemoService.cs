using Microsoft.Extensions.Hosting;
using Microsoft.Extensions.Logging;
using Microsoft.Extensions.Options;
using Phishing_Planet.Options;
using Phishing_Planet.VirusTotal.Models;

namespace Phishing_Planet.VirusTotal;

public sealed class VirusTotalDemoService(
    IVirusTotalClient client,
    VirusTotalRateLimiter rateLimiter,
    IOptions<VirusTotalOptions> options,
    ILogger<VirusTotalDemoService> logger)
    : IHostedService
{
    private const string EicarFileHash = "275a021bbfb6489e54d471899f7db9d1663fc695ec2fe2a2c4538aabf651fd0f";

    public async Task StartAsync(CancellationToken cancellationToken)
    {
        if (!options.Value.RunDemoOnStartup)
            return;

        Console.WriteLine();
        Console.WriteLine("── VirusTotal demo ─────────────────────────────");
        Console.WriteLine(
            $"Rate limits: {options.Value.RequestsPerMinute}/min, " +
            $"{options.Value.RequestsPerDay}/day, " +
            $"{options.Value.RequestsPerMonth}/month");

        try
        {
            var file = await client.GetFileReportAsync(EicarFileHash, cancellationToken);
            PrintFile(file);

            var url = await client.GetUrlReportAsync(
                "https://www.google.com",
                cancellationToken);
            PrintUrl(url);

            var domain = await client.GetDomainReportAsync(
                "google.com",
                cancellationToken);
            PrintDomain(domain);

            var ip = await client.GetIpAddressReportAsync(
                "8.8.8.8",
                cancellationToken);
            PrintIp(ip);

            var status = rateLimiter.GetStatus();
            Console.WriteLine(
                $"Remaining quota — minute: {status.RemainingThisMinute}, " +
                $"day: {status.RemainingToday}, " +
                $"month: {status.RemainingThisMonth}");
        }
        catch (OperationCanceledException) when (cancellationToken.IsCancellationRequested)
        {
        }
        catch (Exception exception)
        {
            logger.LogError(exception, "VirusTotal demo failed");
            Console.WriteLine(
                $"[VirusTotal] Demo failed: {exception.GetType().Name}: {exception.Message}");
        }

        Console.WriteLine("────────────────────────────────────────────────");
    }

    public Task StopAsync(CancellationToken cancellationToken) => Task.CompletedTask;

    private static void PrintFile(VirusTotalObject<VirusTotalFileAttributes> file)
    {
        var attributes = file.Attributes;

        Console.WriteLine();
        Console.WriteLine(
            $"File: {attributes?.MeaningfulName ?? attributes?.Sha256 ?? file.Id}");
        Console.WriteLine($"  Type: {attributes?.TypeDescription ?? "unknown"}");
        Console.WriteLine($"  Reputation: {attributes?.Reputation ?? 0}");
        PrintStats(attributes?.LastAnalysisStats);
        Console.WriteLine(
            $"  Votes: {attributes?.TotalVotes?.Malicious ?? 0} malicious / " +
            $"{attributes?.TotalVotes?.Harmless ?? 0} harmless");
    }

    private static void PrintUrl(VirusTotalObject<UrlAttributes> url)
    {
        var attributes = url.Attributes;

        Console.WriteLine();
        Console.WriteLine($"URL: {attributes?.Url ?? url.Id}");
        Console.WriteLine($"  Title: {attributes?.Title ?? "(none)"}");
        Console.WriteLine($"  Reputation: {attributes?.Reputation ?? 0}");
        PrintStats(attributes?.LastAnalysisStats);
    }

    private static void PrintDomain(VirusTotalObject<DomainAttributes> domain)
    {
        var attributes = domain.Attributes;

        Console.WriteLine();
        Console.WriteLine($"Domain: {domain.Id}");
        Console.WriteLine($"  Registrar: {attributes?.Registrar ?? "unknown"}");
        Console.WriteLine($"  Reputation: {attributes?.Reputation ?? 0}");
        PrintStats(attributes?.LastAnalysisStats);
    }

    private static void PrintIp(VirusTotalObject<IpAddressAttributes> ip)
    {
        var attributes = ip.Attributes;

        Console.WriteLine();
        Console.WriteLine($"IP: {ip.Id}");
        Console.WriteLine(
            $"  Owner: {attributes?.AsOwner ?? "unknown"} " +
            $"(AS{attributes?.Asn?.ToString() ?? "?"})");
        Console.WriteLine($"  Country: {attributes?.Country ?? "unknown"}");
        Console.WriteLine($"  Reputation: {attributes?.Reputation ?? 0}");
        PrintStats(attributes?.LastAnalysisStats);
    }

    private static void PrintStats(AnalysisStats? stats)
    {
        if (stats is null)
        {
            Console.WriteLine("  Detections: (no analysis stats)");
            return;
        }

        Console.WriteLine(
            $"  Detections: {stats.Malicious} malicious, " +
            $"{stats.Suspicious} suspicious, " +
            $"{stats.Harmless} harmless, " +
            $"{stats.Undetected} undetected");
    }
}