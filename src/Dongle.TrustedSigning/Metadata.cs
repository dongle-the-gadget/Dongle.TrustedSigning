using System.Text.Json.Serialization;

namespace Dongle.TrustedSigning;

public class Metadata
{
    public required string Endpoint { get; set; }

    public required string CodeSigningAccountName { get; set; }

    public required string CertificateProfileName { get; set; }

    public string? CorrelationId { get; set; }

    public string? AdditionalInfo { get; set; }

    public IEnumerable<string> ExcludeCredentials { get; set; } = [];

    public string? AccessToken { get; set; }
}

[JsonSerializable(typeof(Metadata))]
[JsonSourceGenerationOptions(GenerationMode = JsonSourceGenerationMode.Metadata)]
public partial class MetadataSerializerContext : JsonSerializerContext;