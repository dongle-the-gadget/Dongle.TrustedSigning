using Microsoft.Win32.SafeHandles;
using System.ComponentModel;
using System.Runtime.InteropServices;
using TerraFX.Interop.Windows;

namespace Dongle.TrustedSigning;

public static unsafe class CATHelpers
{
#pragma warning disable CS0649
    private struct CRYPTCATMEMBER
    {
        public uint cbStruct;
        public char* pwszReferenceTag;
        public char* pwszFileName;
        public Guid gSubjectType;
        public uint fdwMemberFlags;
        public SIP_INDIRECT_DATA* pIndirectData;
        public uint dwCertVersion;
        public uint dwReserved;
        public HANDLE hReserved;
        public CRYPT_DATA_BLOB sEncodedIndirectData;
        public CRYPT_DATA_BLOB sEncodedMemberInfo;
    }
#pragma warning restore CS0649

    [DllImport("wintrust", ExactSpelling = true)]
    private static extern BOOL CryptCATAdminAcquireContext2(HCATADMIN* phCatAdmin, Guid* pgSubsystem, char* pwszHashAlgorithm, CERT_STRONG_SIGN_PARA* pStrongHashPolicy, uint dwFlags);

    [DllImport("wintrust", ExactSpelling = true)]
    private static extern BOOL CryptCATAdminCalcHashFromFileHandle2(HCATADMIN hCatAdmin, HANDLE hFile, uint* pcbHash, byte* pbHash, uint dwFlags);

    [DllImport("wintrust", ExactSpelling = true)]
    private static extern BOOL CryptCATAdminReleaseContext(HCATADMIN hCatAdmin, uint dwFlags);

    [DllImport("wintrust", ExactSpelling = true)]
    private static extern BOOL IsCatalogFile(HANDLE hFile, char* pwszFileName);

    [DllImport("wintrust", ExactSpelling = true)]
    private static extern HANDLE CryptCATOpen(char* pwszFileName, uint fdwOpenFlags, HCRYPTPROV hProv, uint dwPublicVersion, uint dwEncodingType);

    [DllImport("wintrust", ExactSpelling = true)]
    private static extern CRYPTCATMEMBER* CryptCATEnumerateMember(HANDLE hCatalog, CRYPTCATMEMBER* pPrevMember);

    [DllImport("wintrust", ExactSpelling = true)]
    private static extern BOOL CryptCATClose(HANDLE hCatalog);

    public static byte[]? CalculateAuthenticodeHash(SafeFileHandle fileHandle)
    {
        HANDLE hFile = (HANDLE)fileHandle.DangerousGetHandle();
        HCATADMIN hCatAdmin;
        fixed (char* pHashAlgorithm = "SHA256")
        {
            CryptCATAdminAcquireContext2(&hCatAdmin, null, pHashAlgorithm, null, 0);
        }
        uint pcbHash = 16;
        byte* pbHash = stackalloc byte[16];
        if (!CryptCATAdminCalcHashFromFileHandle2(hCatAdmin, hFile, &pcbHash, pbHash, 0))
        {
            pbHash = (byte*)NativeMemory.Alloc(pcbHash);
            if (!CryptCATAdminCalcHashFromFileHandle2(hCatAdmin, hFile, &pcbHash, pbHash, 0))
            {
                CryptCATAdminReleaseContext(hCatAdmin, 0);
                NativeMemory.Free(pbHash);
            }
            byte[] hash = new byte[pcbHash];
            new ReadOnlySpan<byte>(pbHash, (int)pcbHash).CopyTo(hash);
            return hash;
        }
        return null;
    }

    public static bool IsCryptCATFile(SafeFileHandle fileHandle)
    {
        HANDLE hFile = (HANDLE)fileHandle.DangerousGetHandle();
        return IsCatalogFile(hFile, null);
    }

    public static IEnumerable<byte[]> RetrieveFileHashFromCAT(SafeFileHandle fileHandle)
    {
        List<byte[]> hashes = new();
        string tempFileName;
        using (FileStream sourceStream = new(fileHandle, FileAccess.Read))
        {
            string path = $"AXS_{Guid.NewGuid().ToString().Replace("-", "")}_{DateTime.Now.ToString("yyyyMMddHHmmss")}.cat";
            using FileStream destStream = new(Path.Combine(Path.GetTempPath(), path), FileMode.Create);
            sourceStream.CopyTo(destStream);
            tempFileName = destStream.Name;
        }

        // The original implementation checks if the catalog file has the correct GUID,
        // but it doesn't seem to affect the behavior so I'm leaving it out for now.

        HANDLE hCAT;
        fixed (char* lpTempFileName =  tempFileName)
        {
            hCAT = CryptCATOpen(lpTempFileName, 0, HCRYPTPROV.NULL, 0, 0);
        }
        if (hCAT != HANDLE.INVALID_VALUE)
        {
            CRYPTCATMEMBER* lpMember = null;
            while ((lpMember = CryptCATEnumerateMember(hCAT, lpMember)) != null)
            {
                byte[] hash = new byte[lpMember->pIndirectData->Digest.cbData];
                new ReadOnlySpan<byte>(lpMember->pIndirectData->Digest.pbData, (int)lpMember->pIndirectData->Digest.cbData).CopyTo(hash);
                hashes.Add(hash);
            }
            CryptCATClose(hCAT);
            File.Delete(tempFileName);
            return hashes;
        }
        throw new Win32Exception(Marshal.GetLastSystemError());
    }

    public static List<byte[]> GetSigningFileAuthenticodeHashList(SafeFileHandle fileHandle)
    {
        List<byte[]> hashes = new List<byte[]>();
        if (!fileHandle.IsInvalid)
        {
            hashes.Add(CalculateAuthenticodeHash(fileHandle)!);
        }
        if (IsCryptCATFile(fileHandle))
        {
            hashes.AddRange(RetrieveFileHashFromCAT(fileHandle));
        }
        return hashes;
    }
}
