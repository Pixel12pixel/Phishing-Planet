using System.Text.Json;
using System.Text.Json.Serialization;

namespace Phishing_Planet.VirusTotal.Models;

public sealed class VirusTotalFileAttributes
{
    [JsonPropertyName("sha256")]
    public string? Sha256 { get; init; }

    [JsonPropertyName("sha1")]
    public string? Sha1 { get; init; }

    [JsonPropertyName("md5")]
    public string? Md5 { get; init; }

    [JsonPropertyName("meaningful_name")]
    public string? MeaningfulName { get; init; }

    [JsonPropertyName("type_description")]
    public string? TypeDescription { get; init; }

    [JsonPropertyName("size")]
    public long? Size { get; init; }

    [JsonPropertyName("reputation")]
    public int? Reputation { get; init; }

    [JsonPropertyName("total_votes")]
    public TotalVotes? TotalVotes { get; init; }

    [JsonPropertyName("last_analysis_stats")]
    public AnalysisStats? LastAnalysisStats { get; init; }

    [JsonPropertyName("last_analysis_date")]
    public long? LastAnalysisDate { get; init; }

    [JsonPropertyName("first_submission_date")]
    public long? FirstSubmissionDate { get; init; }

    [JsonPropertyName("last_submission_date")]
    public long? LastSubmissionDate { get; init; }

    [JsonPropertyName("times_submitted")]
    public int? TimesSubmitted { get; init; }

    [JsonPropertyName("tags")]
    public List<string>? Tags { get; init; }

    [JsonPropertyName("names")]
    public List<string>? Names { get; init; }

    [JsonPropertyName("last_analysis_results")]
    public Dictionary<string, JsonElement>? LastAnalysisResults { get; init; }

    [JsonExtensionData]
    public Dictionary<string, JsonElement>? Extra { get; init; }
}

public sealed class UrlAttributes
{
    [JsonPropertyName("url")]
    public string? Url { get; init; }

    [JsonPropertyName("title")]
    public string? Title { get; init; }

    [JsonPropertyName("last_final_url")]
    public string? LastFinalUrl { get; init; }

    [JsonPropertyName("reputation")]
    public int? Reputation { get; init; }

    [JsonPropertyName("total_votes")]
    public TotalVotes? TotalVotes { get; init; }

    [JsonPropertyName("last_analysis_stats")]
    public AnalysisStats? LastAnalysisStats { get; init; }

    [JsonPropertyName("last_analysis_date")]
    public long? LastAnalysisDate { get; init; }

    [JsonPropertyName("first_submission_date")]
    public long? FirstSubmissionDate { get; init; }

    [JsonPropertyName("last_submission_date")]
    public long? LastSubmissionDate { get; init; }

    [JsonPropertyName("times_submitted")]
    public int? TimesSubmitted { get; init; }

    [JsonPropertyName("categories")]
    public Dictionary<string, string>? Categories { get; init; }

    [JsonPropertyName("tags")]
    public List<string>? Tags { get; init; }

    [JsonPropertyName("last_analysis_results")]
    public Dictionary<string, JsonElement>? LastAnalysisResults { get; init; }

    [JsonExtensionData]
    public Dictionary<string, JsonElement>? Extra { get; init; }
}

public sealed class DomainAttributes
{
    [JsonPropertyName("reputation")]
    public int? Reputation { get; init; }

    [JsonPropertyName("total_votes")]
    public TotalVotes? TotalVotes { get; init; }

    [JsonPropertyName("last_analysis_stats")]
    public AnalysisStats? LastAnalysisStats { get; init; }

    [JsonPropertyName("last_analysis_date")]
    public long? LastAnalysisDate { get; init; }

    [JsonPropertyName("categories")]
    public Dictionary<string, string>? Categories { get; init; }

    [JsonPropertyName("tags")]
    public List<string>? Tags { get; init; }

    [JsonPropertyName("registrar")]
    public string? Registrar { get; init; }

    [JsonPropertyName("creation_date")]
    public long? CreationDate { get; init; }

    [JsonPropertyName("last_update_date")]
    public long? LastUpdateDate { get; init; }

    [JsonPropertyName("expiration_date")]
    public long? ExpirationDate { get; init; }

    [JsonPropertyName("last_dns_records")]
    public List<JsonElement>? LastDnsRecords { get; init; }

    [JsonPropertyName("last_analysis_results")]
    public Dictionary<string, JsonElement>? LastAnalysisResults { get; init; }

    [JsonExtensionData]
    public Dictionary<string, JsonElement>? Extra { get; init; }
}

public sealed class IpAddressAttributes
{
    [JsonPropertyName("reputation")]
    public int? Reputation { get; init; }

    [JsonPropertyName("total_votes")]
    public TotalVotes? TotalVotes { get; init; }

    [JsonPropertyName("last_analysis_stats")]
    public AnalysisStats? LastAnalysisStats { get; init; }

    [JsonPropertyName("last_analysis_date")]
    public long? LastAnalysisDate { get; init; }

    [JsonPropertyName("country")]
    public string? Country { get; init; }

    [JsonPropertyName("continent")]
    public string? Continent { get; init; }

    [JsonPropertyName("as_owner")]
    public string? AsOwner { get; init; }

    [JsonPropertyName("asn")]
    public long? Asn { get; init; }

    [JsonPropertyName("network")]
    public string? Network { get; init; }

    [JsonPropertyName("regional_internet_registry")]
    public string? RegionalInternetRegistry { get; init; }

    [JsonPropertyName("tags")]
    public List<string>? Tags { get; init; }

    [JsonPropertyName("last_analysis_results")]
    public Dictionary<string, JsonElement>? LastAnalysisResults { get; init; }

    [JsonExtensionData]
    public Dictionary<string, JsonElement>? Extra { get; init; }
}