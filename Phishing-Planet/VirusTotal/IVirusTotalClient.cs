using Phishing_Planet.VirusTotal.Models;
namespace Phishing_Planet.VirusTotal;

public interface IVirusTotalClient
{
    Task<VirusTotalObject<VirusTotalFileAttributes>> GetFileReportAsync(
        string hash,
        CancellationToken cancellationToken = default);
    
    Task<VirusTotalObject<AnalysisAttributes>> UploadFileAsync(
        Stream fileStream,
        string fileName,
        CancellationToken cancellationToken = default);

    Task<VirusTotalObject<AnalysisAttributes>> ScanUrlAsync(
        string url,
        CancellationToken cancellationToken = default);
    
    Task<VirusTotalObject<UrlAttributes>> GetUrlReportAsync(
        string url,
        CancellationToken cancellationToken = default);

    Task<VirusTotalObject<DomainAttributes>> GetDomainReportAsync(
        string domain,
        CancellationToken cancellationToken = default);

    Task<VirusTotalObject<IpAddressAttributes>> GetIpAddressReportAsync(
        string ip,
        CancellationToken cancellationToken = default);

    Task<VirusTotalObject<AnalysisAttributes>> GetAnalysisAsync(
        string analysisId,
        CancellationToken cancellationToken = default);

    Task<VirusTotalObject<AnalysisAttributes>> RescanFileAsync(
        string hash,
        CancellationToken cancellationToken = default);

    Task<string> GetLargeFileUploadUrlAsync(
        CancellationToken cancellationToken = default);
    
    Task<VirusTotalObject<AnalysisAttributes>> UploadLargeFileAsync(
        Stream fileStream,
        string fileName,
        CancellationToken cancellationToken = default);
}