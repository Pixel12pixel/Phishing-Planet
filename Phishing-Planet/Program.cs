using Microsoft.Extensions.DependencyInjection;
using Microsoft.Extensions.Hosting;
using Phishing_Planet.Options;
using Phishing_Planet.Presentation;
using Phishing_Planet.Services;
using System.Net.Http.Headers;
using Microsoft.Extensions.Configuration;
using Microsoft.Extensions.Options;
using Phishing_Planet.VirusTotal;

var builder = Host.CreateApplicationBuilder(args);

builder.Configuration.AddUserSecrets<Program>(optional: true);

var virusTotalApiKey = builder.Configuration[$"{VirusTotalOptions.SectionName}:ApiKey"];

if (!string.IsNullOrWhiteSpace(virusTotalApiKey))
{
    builder.Services
        .AddOptions<VirusTotalOptions>()
        .Bind(builder.Configuration.GetSection(VirusTotalOptions.SectionName))
        .Validate(
            o => !string.IsNullOrWhiteSpace(o.ApiKey),
            "VirusTotal:ApiKey is required.")
        .Validate(
            o => Uri.TryCreate(o.BaseUrl, UriKind.Absolute, out _),
            "VirusTotal:BaseUrl must be an absolute URI.")
        .Validate(
            o => o.RequestsPerMinute > 0,
            "VirusTotal:RequestsPerMinute must be greater than zero.")
        .Validate(
            o => o.RequestsPerDay > 0,
            "VirusTotal:RequestsPerDay must be greater than zero.")
        .Validate(
            o => o.RequestsPerMonth > 0,
            "VirusTotal:RequestsPerMonth must be greater than zero.")
        .ValidateOnStart();

    builder.Services.AddSingleton<VirusTotalRateLimiter>();

    builder.Services
        .AddHttpClient<IVirusTotalClient, VirusTotalClient>((serviceProvider, httpClient) =>
        {
            var virusTotal = serviceProvider
                .GetRequiredService<IOptions<VirusTotalOptions>>()
                .Value;

            var baseUrl = virusTotal.BaseUrl.EndsWith('/')
                ? virusTotal.BaseUrl
                : $"{virusTotal.BaseUrl}/";

            httpClient.BaseAddress = new Uri(baseUrl);
            httpClient.DefaultRequestHeaders.Add(
                "x-apikey",
                virusTotal.ApiKey.Trim());
            httpClient.DefaultRequestHeaders.Accept.Add(
                new MediaTypeWithQualityHeaderValue("application/json"));
            httpClient.DefaultRequestHeaders.UserAgent.ParseAdd(
                "Phishing-Planet/1.0");
            httpClient.Timeout = TimeSpan.FromMinutes(5);
        });

    builder.Services.AddHostedService<VirusTotalDemoService>();
}


builder.Services
    .AddOptions<MailWatcherOptions>()
    .Bind(builder.Configuration.GetSection(MailWatcherOptions.SectionName))
    .Validate(o => !string.IsNullOrWhiteSpace(o.Host), "MailWatcher:Host is required.")
    .Validate(o => o.Port is > 0 and <= 65535, "MailWatcher:Port must be 1–65535.")
    .Validate(o => !string.IsNullOrWhiteSpace(o.Username), "MailWatcher:Username is required.")
    .ValidateOnStart();

builder.Services
    .AddOptions<SmtpOptions>()
    .Bind(builder.Configuration.GetSection(SmtpOptions.SectionName))
    .Validate(o => !string.IsNullOrWhiteSpace(o.Host), "SmtpSender:Host is required.")
    .Validate(o => o.Port is > 0 and <= 65535, "SmtpSender:Port must be 1–65535.")
    .Validate(o => !string.IsNullOrWhiteSpace(o.Username), "SmtpSender:Username is required.")
    .ValidateOnStart();

builder.Services.AddSingleton<IEmailPresenter, EmailConsolePresenter>();

builder.Services.AddHostedService<EmailWatcherService>();

await builder.Build().RunAsync();