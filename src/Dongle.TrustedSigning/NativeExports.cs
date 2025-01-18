using Microsoft.Win32.SafeHandles;
using System.Runtime.InteropServices;
using System.Text.Json;
using TerraFX.Interop.Windows;
using static TerraFX.Interop.Windows.Windows;

namespace Dongle.TrustedSigning;

public static class NativeExports
{
    [UnmanagedCallersOnly(EntryPoint = "AuthenticodeDigestSignExWithFileHandle")]
    public static unsafe int AuthenticodeDigestSignExWithFileHandle(
        CRYPT_DATA_BLOB* pMetadataBlob,
        int digestAlgId,
        byte* pbToBeSignedDigest,
        uint cbToBeSignedDigest,
        HANDLE hFile,
        CRYPT_DATA_BLOB* pSignedDigest,
        CERT_CONTEXT** ppSignerCert,
        HCERTSTORE hCertChainStore)
    {
        Console.WriteLine();
        Console.WriteLine("Trusted Signing");
        Console.WriteLine();
        try
        {
            Metadata metadata = JsonSerializer.Deserialize(new ReadOnlySpan<byte>(pMetadataBlob->pbData, (int)pMetadataBlob->cbData), MetadataSerializerContext.Default.Metadata)!;
            byte[] toBeSignedDigest = new byte[(int)cbToBeSignedDigest];
            new ReadOnlySpan<byte>(pbToBeSignedDigest, (int)cbToBeSignedDigest).CopyTo(toBeSignedDigest);
            SafeFileHandle fileHandle = new((IntPtr)hFile, false);

            Signer.SignerResponse response = Signer.SignAsync(metadata, digestAlgId, toBeSignedDigest, fileHandle).GetAwaiter().GetResult();

            byte* signatureUnmanaged = (byte*)HeapAlloc(GetProcessHeap(), HEAP.HEAP_ZERO_MEMORY, (nuint)response.Signature.LongLength);
            if (signatureUnmanaged == null)
            {
                return E.E_OUTOFMEMORY;
            }
            response.Signature.CopyTo(new Span<byte>(signatureUnmanaged, response.Signature.Length));

            pSignedDigest->pbData = signatureUnmanaged;
            pSignedDigest->cbData = (uint)response.Signature.Length;
            if (response.IssuerCerts != null && response.IssuerCerts.Length > 0)
            {
                foreach (var cert in response.IssuerCerts)
                {
                    CERT_CONTEXT* certContext = CertDuplicateCertificateContext((CERT_CONTEXT*)cert.Handle);
                    if (certContext == null)
                    {
                        return Marshal.GetLastSystemError();
                    }
                    const uint CERT_STORE_ADD_NEW = 1;
                    if (!CertAddCertificateContextToStore(hCertChainStore, certContext, CERT_STORE_ADD_NEW, ppSignerCert))
                    {
                        return Marshal.GetLastSystemError();
                    }
                    CertFreeCertificateContext(certContext);
                }
            }

            if (response.SignerCert != null) // Does this do anything?
            {
                CERT_CONTEXT* certContext = CertDuplicateCertificateContext((CERT_CONTEXT*)response.SignerCert.Handle);
                if (certContext == null)
                {
                    return Marshal.GetLastSystemError();
                }
                const uint CERT_STORE_ADD_NEW = 1;
                if (!CertAddCertificateContextToStore(hCertChainStore, certContext, CERT_STORE_ADD_NEW, ppSignerCert))
                {
                    return Marshal.GetLastSystemError();
                }
                CertFreeCertificateContext(certContext);
            }

            return S.S_OK;
        }
        catch (Exception ex)
        {
            Console.Error.WriteLine("Unhandled managed exception");
            Console.Error.WriteLine(ex);
            Console.WriteLine();
            return E.E_FAIL;
        }
    }
}