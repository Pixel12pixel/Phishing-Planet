using System.Text.Json;
using System.Text.Json.Serialization;

namespace Phishing_Planet.VirusTotal.Models;

public sealed class VirusTotalResponse<T>
{
    [JsonPropertyName("data")]
    public T? Data { get; init; }

    [JsonPropertyName("meta")]
    public JsonElement? Meta { get; init; }

    [JsonPropertyName("links")]
    public JsonElement? Links { get; init; }
}

public sealed class VirusTotalObject<TAttributes>
{
    [JsonPropertyName("type")]
    public string Type { get; init; } = string.Empty;

    [JsonPropertyName("id")]
    public string Id { get; init; } = string.Empty;

    [JsonPropertyName("attributes")]
    public TAttributes? Attributes { get; init; }

    [JsonExtensionData]
    public Dictionary<string, JsonElement>? Extra { get; init; }
}

public sealed class AnalysisStats
{
    [JsonPropertyName("harmless")]
    public int Harmless { get; init; }

    [JsonPropertyName("malicious")]
    public int Malicious { get; init; }

    [JsonPropertyName("suspicious")]
    public int Suspicious { get; init; }

    [JsonPropertyName("undetected")]
    public int Undetected { get; init; }

    [JsonPropertyName("timeout")]
    public int Timeout { get; init; }

    [JsonPropertyName("failure")]
    public int Failure { get; init; }

    [JsonPropertyName("type-unsupported")]
    public int TypeUnsupported { get; init; }

    [JsonPropertyName("confirmed-timeout")]
    public int ConfirmedTimeout { get; init; }

    public int Detections => Malicious + Suspicious;

    public int Total =>
        Harmless + Malicious + Suspicious + Undetected +
        Timeout + Failure + TypeUnsupported + ConfirmedTimeout;
}

public sealed class TotalVotes
{
    [JsonPropertyName("harmless")]
    public int Harmless { get; init; }

    [JsonPropertyName("malicious")]
    public int Malicious { get; init; }
}

public sealed class AnalysisAttributes
{
    [JsonPropertyName("status")]
    public string? Status { get; init; }

    [JsonPropertyName("date")]
    public long? Date { get; init; }

    [JsonPropertyName("stats")]
    public AnalysisStats? Stats { get; init; }

    [JsonPropertyName("results")]
    public Dictionary<string, JsonElement>? Results { get; init; }

    [JsonExtensionData]
    public Dictionary<string, JsonElement>? Extra { get; init; }
}