using Microsoft.Extensions.Options;
using Phishing_Planet.Options;

namespace Phishing_Planet.VirusTotal;

public readonly record struct VirusTotalRateLimitStatus(
    int RemainingThisMinute,
    int RemainingToday,
    int RemainingThisMonth);

public sealed class VirusTotalRateLimiter
{
    private readonly Lock _gate = new();
    private readonly Queue<DateTimeOffset> _minuteWindow = new();
    private readonly int _perMinute;
    private readonly int _perDay;
    private readonly int _perMonth;

    private DateOnly _currentDay;
    private int _dayCount;
    private int _currentMonth;
    private int _currentYear;
    private int _monthCount;

    public VirusTotalRateLimiter(IOptions<VirusTotalOptions> options)
    {
        var value = options.Value;

        if (value.RequestsPerMinute <= 0)
            throw new ArgumentOutOfRangeException(
                nameof(options),
                "VirusTotal:RequestsPerMinute must be greater than zero.");

        if (value.RequestsPerDay <= 0)
            throw new ArgumentOutOfRangeException(
                nameof(options),
                "VirusTotal:RequestsPerDay must be greater than zero.");

        if (value.RequestsPerMonth <= 0)
            throw new ArgumentOutOfRangeException(
                nameof(options),
                "VirusTotal:RequestsPerMonth must be greater than zero.");

        _perMinute = value.RequestsPerMinute;
        _perDay = value.RequestsPerDay;
        _perMonth = value.RequestsPerMonth;

        var now = DateTimeOffset.UtcNow;
        _currentDay = DateOnly.FromDateTime(now.UtcDateTime);
        _currentYear = now.Year;
        _currentMonth = now.Month;
    }
    
    public async Task AcquireAsync(CancellationToken cancellationToken = default)
    {
        while (true)
        {
            TimeSpan delay;

            lock (_gate)
            {
                var now = DateTimeOffset.UtcNow;
                RollWindows(now);
                PruneMinuteWindow(now);

                if (_minuteWindow.Count < _perMinute &&
                    _dayCount < _perDay &&
                    _monthCount < _perMonth)
                {
                    _minuteWindow.Enqueue(now);
                    _dayCount++;
                    _monthCount++;
                    return;
                }

                delay = GetDelay(now);
            }

            if (delay <= TimeSpan.Zero)
                delay = TimeSpan.FromMilliseconds(100);

            await Task.Delay(delay, cancellationToken).ConfigureAwait(false);
        }
    }

    public VirusTotalRateLimitStatus GetStatus()
    {
        lock (_gate)
        {
            var now = DateTimeOffset.UtcNow;
            RollWindows(now);
            PruneMinuteWindow(now);

            return new VirusTotalRateLimitStatus(
                Math.Max(0, _perMinute - _minuteWindow.Count),
                Math.Max(0, _perDay - _dayCount),
                Math.Max(0, _perMonth - _monthCount));
        }
    }

    private void RollWindows(DateTimeOffset now)
    {
        var day = DateOnly.FromDateTime(now.UtcDateTime);

        if (day != _currentDay)
        {
            _currentDay = day;
            _dayCount = 0;
        }

        if (now.Year == _currentYear && now.Month == _currentMonth) return;
        _currentYear = now.Year;
        _currentMonth = now.Month;
        _monthCount = 0;
    }

    private void PruneMinuteWindow(DateTimeOffset now)
    {
        var cutoff = now - TimeSpan.FromMinutes(1);

        while (_minuteWindow.Count > 0 && _minuteWindow.Peek() <= cutoff)
            _minuteWindow.Dequeue();
    }

    private TimeSpan GetDelay(DateTimeOffset now)
    {
        if (_dayCount >= _perDay)
            return NextUtcMidnight(now) - now;

        if (_monthCount >= _perMonth)
            return NextUtcMonth(now) - now;

        if (_minuteWindow.Count <= 0) return TimeSpan.FromMilliseconds(100);
        var readyAt = _minuteWindow.Peek() + TimeSpan.FromMinutes(1);
        var delay = readyAt - now;
        return delay > TimeSpan.Zero
            ? delay
            : TimeSpan.FromMilliseconds(100);

    }

    private static DateTimeOffset NextUtcMidnight(DateTimeOffset now)
    {
        var nextDay = now.UtcDateTime.Date.AddDays(1);
        return new DateTimeOffset(nextDay, TimeSpan.Zero);
    }

    private static DateTimeOffset NextUtcMonth(DateTimeOffset now)
    {
        var nextMonth = new DateTime(
            now.Year,
            now.Month,
            1,
            0,
            0,
            0,
            DateTimeKind.Utc).AddMonths(1);

        return new DateTimeOffset(nextMonth, TimeSpan.Zero);
    }
}