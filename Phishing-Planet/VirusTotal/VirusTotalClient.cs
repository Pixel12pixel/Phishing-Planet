using System.Buffers.Text;
using System.Net;
using System.Net.Http.Headers;
using System.Text;
using System.Text.Json;
using Microsoft.Extensions.Logging;
using Phishing_Planet.VirusTotal.Models;

namespace Phishing_Planet.VirusTotal;

public sealed class VirusTotalClient(
    HttpClient httpClient,
    IHttpClientFactory httpClientFactory,
    VirusTotalRateLimiter rateLimiter,
    ILogger<VirusTotalClient> logger)
    : IVirusTotalClient
{
    private const int MaxRetryAttempts = 3;

    private static readonly JsonSerializerOptions JsonOptions = new(JsonSerializerDefaults.Web)
    {
        PropertyNameCaseInsensitive = true
    };
    
    public Task<VirusTotalObject<VirusTotalFileAttributes>> GetFileReportAsync(
        string hash,
        CancellationToken cancellationToken = default)
    {
        ArgumentException.ThrowIfNullOrWhiteSpace(hash);

        return GetReportAsync<VirusTotalFileAttributes>(
            $"files/{Uri.EscapeDataString(hash)}",
            cancellationToken);
    }

    public async Task<VirusTotalObject<AnalysisAttributes>> UploadFileAsync(
        Stream fileStream,
        string fileName,
        CancellationToken cancellationToken = default)
    {
        ArgumentNullException.ThrowIfNull(fileStream);
        ArgumentException.ThrowIfNullOrWhiteSpace(fileName);

        await rateLimiter.AcquireAsync(cancellationToken).ConfigureAwait(false);

        using var content = new MultipartFormDataContent();
        using var streamContent = new StreamContent(fileStream);
        streamContent.Headers.ContentType =
            new MediaTypeHeaderValue("application/octet-stream");
        content.Add(streamContent, "file", fileName);

        using var response = await httpClient
            .PostAsync("files", content, cancellationToken)
            .ConfigureAwait(false);

        var body = await response.Content
            .ReadAsStringAsync(cancellationToken)
            .ConfigureAwait(false);

        if (!response.IsSuccessStatusCode)
            throw VirusTotalException.Create(
                response.StatusCode,
                body,
                response.Headers.RetryAfter);

        return Deserialize<VirusTotalResponse<VirusTotalObject<AnalysisAttributes>>>(body).Data
               ?? throw new VirusTotalException(
                   response.StatusCode,
                   "invalid_response",
                   "VirusTotal returned no analysis object.");
    }

    public async Task<VirusTotalObject<AnalysisAttributes>> RescanFileAsync(
        string hash,
        CancellationToken cancellationToken = default)
    {
        ArgumentException.ThrowIfNullOrWhiteSpace(hash);

        var response = await SendAsync<VirusTotalResponse<VirusTotalObject<AnalysisAttributes>>>(
            () => new HttpRequestMessage(
                HttpMethod.Post,
                $"files/{Uri.EscapeDataString(hash)}/analyse"),
            cancellationToken).ConfigureAwait(false);

        return response.Data
               ?? throw new VirusTotalException(
                   HttpStatusCode.OK,
                   "invalid_response",
                   "VirusTotal returned no analysis object.");
    }

    public async Task<string> GetLargeFileUploadUrlAsync(
        CancellationToken cancellationToken = default)
    {
        var response = await SendAsync<VirusTotalResponse<string>>(
            () => new HttpRequestMessage(HttpMethod.Get, "files/upload_url"),
            cancellationToken).ConfigureAwait(false);

        return response.Data
               ?? throw new VirusTotalException(
                   HttpStatusCode.OK,
                   "invalid_response",
                   "VirusTotal returned no upload URL.");
    }

    public async Task<VirusTotalObject<AnalysisAttributes>> UploadLargeFileAsync(
        Stream fileStream,
        string fileName,
        CancellationToken cancellationToken = default)
    {
        ArgumentNullException.ThrowIfNull(fileStream);
        ArgumentException.ThrowIfNullOrWhiteSpace(fileName);

        var uploadUrl = await GetLargeFileUploadUrlAsync(cancellationToken)
            .ConfigureAwait(false);

        await rateLimiter.AcquireAsync(cancellationToken).ConfigureAwait(false);

        using var content = new MultipartFormDataContent();
        using var streamContent = new StreamContent(fileStream);
        streamContent.Headers.ContentType =
            new MediaTypeHeaderValue("application/octet-stream");
        content.Add(streamContent, "file", fileName);
        
        using var uploadClient = httpClientFactory.CreateClient();
        uploadClient.Timeout = TimeSpan.FromMinutes(30);

        using var response = await uploadClient
            .PostAsync(uploadUrl, content, cancellationToken)
            .ConfigureAwait(false);

        var body = await response.Content
            .ReadAsStringAsync(cancellationToken)
            .ConfigureAwait(false);

        if (!response.IsSuccessStatusCode)
            throw VirusTotalException.Create(
                response.StatusCode,
                body,
                response.Headers.RetryAfter);

        return Deserialize<VirusTotalResponse<VirusTotalObject<AnalysisAttributes>>>(body).Data
               ?? throw new VirusTotalException(
                   response.StatusCode,
                   "invalid_response",
                   "VirusTotal returned no analysis object.");
    }
    
    public async Task<VirusTotalObject<AnalysisAttributes>> ScanUrlAsync(
        string url,
        CancellationToken cancellationToken = default)
    {
        ArgumentException.ThrowIfNullOrWhiteSpace(url);

        var response = await SendAsync<VirusTotalResponse<VirusTotalObject<AnalysisAttributes>>>(
            () => new HttpRequestMessage(HttpMethod.Post, "urls")
            {
                Content = new FormUrlEncodedContent(
                    new Dictionary<string, string> { ["url"] = url })
            },
            cancellationToken).ConfigureAwait(false);

        return response.Data
               ?? throw new VirusTotalException(
                   HttpStatusCode.OK,
                   "invalid_response",
                   "VirusTotal returned no analysis object.");
    }

    public Task<VirusTotalObject<UrlAttributes>> GetUrlReportAsync(
        string url,
        CancellationToken cancellationToken = default)
    {
        ArgumentException.ThrowIfNullOrWhiteSpace(url);

        var id = Base64Url.EncodeToString(Encoding.UTF8.GetBytes(url));

        return GetReportAsync<UrlAttributes>($"urls/{id}", cancellationToken);
    }
    
    public Task<VirusTotalObject<DomainAttributes>> GetDomainReportAsync(
        string domain,
        CancellationToken cancellationToken = default)
    {
        ArgumentException.ThrowIfNullOrWhiteSpace(domain);

        return GetReportAsync<DomainAttributes>(
            $"domains/{Uri.EscapeDataString(domain)}",
            cancellationToken);
    }

    public Task<VirusTotalObject<IpAddressAttributes>> GetIpAddressReportAsync(
        string ip,
        CancellationToken cancellationToken = default)
    {
        ArgumentException.ThrowIfNullOrWhiteSpace(ip);

        return GetReportAsync<IpAddressAttributes>(
            $"ip_addresses/{Uri.EscapeDataString(ip)}",
            cancellationToken);
    }
    
    public Task<VirusTotalObject<AnalysisAttributes>> GetAnalysisAsync(
        string analysisId,
        CancellationToken cancellationToken = default)
    {
        ArgumentException.ThrowIfNullOrWhiteSpace(analysisId);

        return GetReportAsync<AnalysisAttributes>(
            $"analyses/{Uri.EscapeDataString(analysisId)}",
            cancellationToken);
    }
    
    private async Task<VirusTotalObject<TAttributes>> GetReportAsync<TAttributes>(
        string relativePath,
        CancellationToken cancellationToken)
    {
        var response = await SendAsync<VirusTotalResponse<VirusTotalObject<TAttributes>>>(
            () => new HttpRequestMessage(HttpMethod.Get, relativePath),
            cancellationToken).ConfigureAwait(false);

        return response.Data
               ?? throw new VirusTotalException(
                   HttpStatusCode.OK,
                   "invalid_response",
                   "VirusTotal returned no data object.");
    }

    private async Task<T> SendAsync<T>(
        Func<HttpRequestMessage> requestFactory,
        CancellationToken cancellationToken)
    {
        for (var attempt = 1; ; attempt++)
        {
            await rateLimiter.AcquireAsync(cancellationToken).ConfigureAwait(false);

            using var request = requestFactory();
            using var response = await httpClient
                .SendAsync(
                    request,
                    HttpCompletionOption.ResponseHeadersRead,
                    cancellationToken)
                .ConfigureAwait(false);

            var body = await response.Content
                .ReadAsStringAsync(cancellationToken)
                .ConfigureAwait(false);

            if (response.StatusCode == HttpStatusCode.TooManyRequests &&
                attempt < MaxRetryAttempts)
            {
                var retryAfter = GetRetryAfter(response) ?? TimeSpan.FromSeconds(60);

                if (retryAfter <= TimeSpan.Zero)
                    retryAfter = TimeSpan.FromSeconds(1);

                logger.LogWarning(
                    "VirusTotal returned HTTP 429. Retrying in {RetryAfter} " +
                    "(attempt {Attempt}/{MaxAttempts}).",
                    retryAfter,
                    attempt,
                    MaxRetryAttempts);

                await Task.Delay(retryAfter, cancellationToken).ConfigureAwait(false);
                continue;
            }

            if (!response.IsSuccessStatusCode)
                throw VirusTotalException.Create(
                    response.StatusCode,
                    body,
                    response.Headers.RetryAfter);

            return Deserialize<T>(body);
        }
    }

    private static TimeSpan? GetRetryAfter(HttpResponseMessage response)
    {
        var retryAfter = response.Headers.RetryAfter;

        if (retryAfter?.Delta is { } delta)
            return delta;

        if (retryAfter?.Date is { } date)
            return date - DateTimeOffset.UtcNow;

        return null;
    }

    private static T Deserialize<T>(string body)
    {
        try
        {
            return JsonSerializer.Deserialize<T>(body, JsonOptions)
                   ?? throw new VirusTotalException(
                       HttpStatusCode.OK,
                       "invalid_response",
                       "VirusTotal returned an empty response body.");
        }
        catch (JsonException exception)
        {
            throw new VirusTotalException(
                HttpStatusCode.OK,
                "invalid_json",
                "VirusTotal returned a response that could not be deserialized.",
                innerException: exception);
        }
    }
}