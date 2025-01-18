using Azure.CodeSigning;
using Azure.CodeSigning.Models;
using Azure.Core;
using Azure.Identity;
using Microsoft.Win32.SafeHandles;
using System.Diagnostics;
using System.Security.Cryptography;
using System.Security.Cryptography.X509Certificates;
using System.Text;
using System.Text.Json;
using System.Text.Json.Serialization;

namespace Dongle.TrustedSigning;

public static partial class Signer
{
    public class EphemeralSignStatus
    {
        public required Guid OperationId { get; init; }

        public required string Status { get; init; }
    }

    [JsonSerializable(typeof(EphemeralSignStatus))]
    [JsonSourceGenerationOptions(GenerationMode = JsonSourceGenerationMode.Metadata, PropertyNamingPolicy = JsonKnownNamingPolicy.CamelCase)]
    public partial class EphemeralSignStatusMetadataProvider : JsonSerializerContext;

    public class SignerResponse
    {
        public required byte[] Signature { get; set; }

        public required X509Certificate2 SignerCert { get; set; }

        public required X509Certificate2[] IssuerCerts { get; set; }
    }

    public static async Task<SignerResponse> SignAsync(Metadata metadata, int digestAlgId, byte[] toBeSignedDigest, SafeFileHandle fileHandle, CancellationToken cancellationToken = default)
    {
        CertificateProfileClientOptions certificateProfileClientOptions = new();
        certificateProfileClientOptions.Diagnostics.IsLoggingContentEnabled = false;
        certificateProfileClientOptions.Diagnostics.IsTelemetryEnabled = false;
        certificateProfileClientOptions.Diagnostics.IsLoggingEnabled = false;

        TokenCredential credential;
        if (!string.IsNullOrEmpty(metadata.AccessToken))
        {
            credential = new UserSuppliedCredential(metadata.AccessToken, DateTimeOffset.Now.AddDays(1));
        }
        else
        {
            DefaultAzureCredentialOptions defaultCredentialOptions = new();
            bool invalidOption = false;
            foreach (string excludeCredential in metadata.ExcludeCredentials)
            {
                if (excludeCredential.Equals("EnvironmentCredential", StringComparison.OrdinalIgnoreCase))
                {
                    defaultCredentialOptions.ExcludeEnvironmentCredential = true;
                }
                else if (excludeCredential.Equals("ManagedIdentityCredential", StringComparison.OrdinalIgnoreCase))
                {
                    defaultCredentialOptions.ExcludeManagedIdentityCredential = true;
                }
                else if (excludeCredential.Equals("WorkloadIdentityCredential", StringComparison.OrdinalIgnoreCase))
                {
                    defaultCredentialOptions.ExcludeWorkloadIdentityCredential = true;
                }
                else if (excludeCredential.Equals("SharedTokenCacheCredential", StringComparison.OrdinalIgnoreCase))
                {
                    defaultCredentialOptions.ExcludeSharedTokenCacheCredential = true;
                }
                else if (excludeCredential.Equals("VisualStudioCredential", StringComparison.OrdinalIgnoreCase))
                {
                    defaultCredentialOptions.ExcludeVisualStudioCredential = true;
                }
                else if (excludeCredential.Equals("VisualStudioCodeCredential", StringComparison.OrdinalIgnoreCase))
                {
                    defaultCredentialOptions.ExcludeVisualStudioCodeCredential = true;
                }
                else if (excludeCredential.Equals("AzureCliCredential", StringComparison.OrdinalIgnoreCase))
                {
                    defaultCredentialOptions.ExcludeAzureCliCredential = true;
                }
                else if (excludeCredential.Equals("AzurePowerShellCredential", StringComparison.OrdinalIgnoreCase))
                {
                    defaultCredentialOptions.ExcludeAzurePowerShellCredential = true;
                }
                else if (excludeCredential.Equals("AzureDeveloperCliCredential", StringComparison.OrdinalIgnoreCase))
                {
                    defaultCredentialOptions.ExcludeAzureDeveloperCliCredential = true;
                }
                else if (excludeCredential.Equals("InteractiveBrowserCredential", StringComparison.OrdinalIgnoreCase))
                {
                    defaultCredentialOptions.ExcludeInteractiveBrowserCredential = true;
                }
                else
                {
                    Console.WriteLine($"The user supplied ExcludedCredentials type {excludeCredential} is not a valid option.");
                    invalidOption = true;
                }
            }

            if (invalidOption)
            {
                Console.WriteLine("These are the options: EnvironmentCredential, ManagedIdentityCredential, WorkloadIdentityCredential, SharedTokenCacheCredential, VisualStudioCredential, VisualStudioCodeCredential, AzureCliCredential, AzurePowerShellCredential, AzureDeveloperCliCredential, InteractiveBrowserCredential");
                throw new ArgumentException("Invalid value for 'ExcludedCredentials' in JSON file");
            }

            credential = new DefaultAzureCredential(defaultCredentialOptions);
        }

        CertificateProfileClient client = new(credential, new Uri(metadata.Endpoint), certificateProfileClientOptions);
        string correlationId = metadata.CorrelationId ?? Guid.NewGuid().ToString();

        List<byte[]> signingFileHashList = new(1);
        if (!fileHandle.IsInvalid)
        {
            using FileStream fileStream = new(fileHandle, FileAccess.Read);
            signingFileHashList.Add(SHA256.HashData(fileStream));
        }
        List<byte[]> signingFileAuthenticodeList = CATHelpers.GetSigningFileAuthenticodeHashList(fileHandle);
        (SignatureAlgorithm SignatureAlgo, HashAlgorithmName HashAlgoName) algoTuple = digestAlgId switch
        {
            32780 => (SignatureAlgorithm.RS256, HashAlgorithmName.SHA256),
            32781 => (SignatureAlgorithm.RS384, HashAlgorithmName.SHA384),
            32782 => (SignatureAlgorithm.RS512, HashAlgorithmName.SHA512),
            _ => throw new ArgumentException("Invalid value for 'digestAlgId' from signtool.")
        };
        SignRequest signRequest = new(algoTuple.SignatureAlgo, toBeSignedDigest)
        {
            FileHashList = signingFileHashList,
            AuthenticodeHashList = signingFileAuthenticodeList
        };
        Console.WriteLine("Submitting digest for signing...");
        Stopwatch stopwatch = Stopwatch.StartNew();
        CertificateProfileSignOperation signOperation = await client.StartSignAsync(metadata.CodeSigningAccountName, metadata.CertificateProfileName, signRequest, correlationId, cancellationToken: cancellationToken);
        EphemeralSignStatus ephemeralSignStatus = JsonSerializer.Deserialize(signOperation.GetRawResponse().Content, EphemeralSignStatusMetadataProvider.Default.EphemeralSignStatus)!;
        Console.WriteLine();
        Console.WriteLine($"OperationId {ephemeralSignStatus.OperationId}: {ephemeralSignStatus.Status}");
        SignStatus finishedSignStatus = await signOperation.WaitForCompletionAsync(cancellationToken);
        stopwatch.Stop();
        Console.WriteLine();
        Console.WriteLine($"Signing completed with status '{finishedSignStatus.Status}' in {stopwatch.Elapsed.TotalSeconds}s");
        Console.WriteLine();
        // For whatever reason, Azure Trusted Signing encodes the certificate as Base64 twice.
        byte[] actualCert = Convert.FromBase64String(Encoding.UTF8.GetString(finishedSignStatus.SigningCertificate));
        System.Security.Cryptography.Pkcs.SignedCms cms = new();
        cms.Decode(actualCert);
        X509Certificate2Collection certificates = cms.Certificates;
#pragma warning restore SYSLIB0057 // No alternatives exist.
        IEnumerable<string> issuers = certificates.Select(x => x.Issuer);
        X509Certificate2 cert = certificates.FirstOrDefault(x => !issuers.Contains(x.Subject)) ?? throw new InvalidOperationException("Unable to locate leaf certificate");
        if (!cert.GetRSAPublicKey()!.VerifyHash(toBeSignedDigest, finishedSignStatus.Signature, algoTuple.HashAlgoName, RSASignaturePadding.Pkcs1))
        {
            throw new CryptographicException("Invalid signature");
        }
        certificates.Remove(cert);
        X509Certificate2[] resultCerts = new X509Certificate2[certificates.Count];
        certificates.CopyTo(resultCerts, 0);
        return new SignerResponse
        {
            Signature = finishedSignStatus.Signature,
            SignerCert = cert,
            IssuerCerts = resultCerts
        };
    }
}