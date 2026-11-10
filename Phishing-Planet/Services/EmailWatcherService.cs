using MailKit;
using MailKit.Net.Imap;
using MailKit.Search;
using MailKit.Security;
using Microsoft.Extensions.Hosting;
using Microsoft.Extensions.Logging;
using Microsoft.Extensions.Options;
using Phishing_Planet.Options;
using Phishing_Planet.Presentation;

namespace Phishing_Planet.Services;

public sealed class EmailWatcherService(
    IOptions<MailWatcherOptions> options,
    IEmailPresenter presenter,
    ILogger<EmailWatcherService> logger)
    : BackgroundService
{
    private readonly MailWatcherOptions _options = options.Value;
    private readonly HashSet<UniqueId> _seenUids = [];

    protected override async Task ExecuteAsync(CancellationToken stoppingToken)
    {
        presenter.ShowInfo(
            $"Connecting to {_options.Host}:{_options.Port} as {_options.Username}…");

        var secure = _options.UseTls
            ? SecureSocketOptions.StartTls
            : SecureSocketOptions.None;

        var firstPass = true;

        while (!stoppingToken.IsCancellationRequested)
        {
            try
            {
                using var client = new ImapClient();
                await client.ConnectAsync(_options.Host, _options.Port, secure, stoppingToken);
                await client.AuthenticateAsync(_options.Username, _options.Password, stoppingToken);
                await client.Inbox.OpenAsync(FolderAccess.ReadOnly, stoppingToken);

                var uids = await client.Inbox.SearchAsync(SearchQuery.All, stoppingToken);

                foreach (var uid in uids)
                {
                    if (!_seenUids.Add(uid))
                        continue;

                    var message = await client.Inbox.GetMessageAsync(uid, stoppingToken);
                    presenter.ShowEmail(message);
                }

                await client.DisconnectAsync(true, stoppingToken);

                if (firstPass)
                {
                    presenter.ShowInfo("Watching inbox for new messages…");
                    firstPass = false;
                }
            }
            catch (OperationCanceledException) when (stoppingToken.IsCancellationRequested)
            {
                break;
            }
            catch (Exception ex)
            {
                logger.LogWarning(ex, "Polling failed");
                presenter.ShowError(ex);
            }

            try
            {
                await Task.Delay(
                    TimeSpan.FromSeconds(_options.PollIntervalSeconds),
                    stoppingToken);
            }
            catch (OperationCanceledException)
            {
                break;
            }
        }
    }
}