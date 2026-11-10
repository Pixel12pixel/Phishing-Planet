using Microsoft.Extensions.DependencyInjection;
using Microsoft.Extensions.Hosting;
using Phishing_Planet.Options;
using Phishing_Planet.Presentation;
using Phishing_Planet.Services;

var builder = Host.CreateApplicationBuilder(args);

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