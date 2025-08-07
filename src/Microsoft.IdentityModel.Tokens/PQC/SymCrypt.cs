// Copyright (c) Microsoft Corporation. All rights reserved.
// Licensed under the MIT License.

using System;
using System.Runtime.InteropServices;

namespace Microsoft.IdentityModel.Tokens
{
    /// <summary>
    /// This class provides P/Invoke methods structures and errors for calling into SymCrypt.dll.
    /// The plan is to expand to include RSA and ECC for comparisons .net.
    /// </summary>
    internal static class SymCrypt
    {
#pragma warning disable SYSLIB1054 // Use 'LibraryImportAttribute' instead of 'DllImportAttribute' to generate P/Invoke marshalling code at compile time

        // The placement of the DLL is important. The DLL is in the PQC folder.
        // This dll is from: https://github.com/microsoft/SymCrypt/releases
        private const string DllName = "PQC/SymCrypt.dll";
        public const int SYMCRYPT_RSAKEY_MAX_NUMOF_PRIMES = 2;
        public const int SYMCRYPT_RSAKEY_MAX_NUMOF_PUBEXPS = 1;
        public const int SYMCRYPT_RSAKEY_MIN_BITSIZE_MODULUS = 256;
        public const int SYMCRYPT_RSAKEY_MAX_BITSIZE_MODULUS = (1 << 16);           // Avoid any integer overflows in size calculations

        // RSA FIPS self-tests require at least 496 bits to avoid fatal
        // Require caller to specify NO_FIPS for up to 1024 bits as running FIPS tests on too-small keys
        // does not make it FIPS certifiable and gives the wrong impression to callers
        public const int SYMCRYPT_RSAKEY_FIPS_MIN_BITSIZE_MODULUS = 1024;
        public const int SYMCRYPT_RSAKEY_MIN_BITSIZE_PRIME = 128;
        public const int SYMCRYPT_RSAKEY_MAX_BITSIZE_PRIME = SYMCRYPT_RSAKEY_MAX_BITSIZE_MODULUS / 2;

        //typedef _Return_type_success_( return == SYMCRYPT_NO_ERROR ) enum {
        //    SYMCRYPT_NO_ERROR = 0,
        //    SYMCRYPT_UNUSED = 0x8000, // Start our error codes here so they're easier to distinguish
        //    SYMCRYPT_WRONG_KEY_SIZE, 32769
        //    SYMCRYPT_WRONG_BLOCK_SIZE,
        //    SYMCRYPT_WRONG_DATA_SIZE,
        //    SYMCRYPT_WRONG_NONCE_SIZE,
        //    SYMCRYPT_WRONG_TAG_SIZE,
        //    SYMCRYPT_WRONG_ITERATION_COUNT,
        //    SYMCRYPT_AUTHENTICATION_FAILURE,
        //    SYMCRYPT_EXTERNAL_FAILURE,
        //    SYMCRYPT_FIPS_FAILURE,
        //    SYMCRYPT_HARDWARE_FAILURE,
        //    SYMCRYPT_NOT_IMPLEMENTED,
        //    SYMCRYPT_INVALID_BLOB,
        //    SYMCRYPT_BUFFER_TOO_SMALL,
        //    SYMCRYPT_INVALID_ARGUMENT, // 0x800E, 32782
        //    SYMCRYPT_MEMORY_ALLOCATION_FAILURE,
        //    SYMCRYPT_SIGNATURE_VERIFICATION_FAILURE,
        //    SYMCRYPT_INCOMPATIBLE_FORMAT,
        //    SYMCRYPT_VALUE_TOO_LARGE,
        //    SYMCRYPT_SESSION_REPLAY_FAILURE,
        //    SYMCRYPT_HBS_NO_OTS_KEYS_LEFT,
        //    SYMCRYPT_HBS_PUBLIC_ROOT_MISMATCH,
        //}
        //SYMCRYPT_ERROR;

        #region HMAC
        [DllImport(DllName, CallingConvention = CallingConvention.Cdecl)]
        public static extern void SymCryptHmacSha256(
            byte[] expandedKey,
            byte[] pbData,
            int cbData,
            byte[] pbResult);

        [DllImport(DllName, CallingConvention = CallingConvention.Cdecl)]
        public static extern void SymCryptHmacSha256ExpandKey(
            out SYMCRYPT_HMAC_SHA256_EXPANDED_KEY pExpandedKey,
            byte[] pbKey,
            int cbKey);
        #endregion

        #region SHA256
        [DllImport(DllName, CallingConvention = CallingConvention.Cdecl)]
        public static extern void SymCryptSha256(
            byte[] pbData,
            long cbData,
            byte[] pbResult);
        #endregion

        #region RSA
        [DllImport(DllName, CallingConvention = CallingConvention.Cdecl)]
        public static extern IntPtr SymCryptRsakeyAllocate(
            ref SYMCRYPT_RSA_PARAMS rsaParams,
            uint flags);

        [DllImport(DllName, CallingConvention = CallingConvention.Cdecl)]
        public static extern uint SymCryptSizeofRsakeyFromParams(ref SYMCRYPT_RSA_PARAMS pParams);

        [DllImport(DllName, CallingConvention = CallingConvention.Cdecl)]
        public static extern IntPtr SymCryptRsakeyCreate(
            byte[] pbBuffer,
            long cbBuffer,
            ref SYMCRYPT_RSA_PARAMS pParams);

        [DllImport(DllName, CallingConvention = CallingConvention.Cdecl)]
        public static extern bool SymCryptRsakeyHasPrivateKey(IntPtr rsaKey);

        [DllImport(DllName, CallingConvention = CallingConvention.Cdecl)]
        public static extern int SymCryptRsaPssSign(
            IntPtr pkRsakey,
            byte[] pbHashValue,
            long cbHashValue,
            IntPtr hashAlgorithm,
            long cbSalt,
            uint flags,
            SYMCRYPT_NUMBER_FORMAT numberFormat,
            byte[] pbSignature,
            long cbSignature,
            ref long cbSignatureOut);

        [DllImport(DllName, CallingConvention = CallingConvention.Cdecl)]
        internal static extern int SymCryptRsakeyGenerate(
            IntPtr pkRsakey,
            [In] ulong[] pu64PubExp,
            uint nPubExp,
            uint flags);

        [DllImport(DllName, CallingConvention = CallingConvention.Cdecl)]
        public static extern IntPtr SymCryptSha256Algorithm();

        #endregion

        #region ML-DSA
        [DllImport(DllName, CallingConvention = CallingConvention.Cdecl)]
        public static extern IntPtr SymCryptMlDsakeyAllocate(
            SYMCRYPT_MLDSA_PARAMS_ENUM mldsa_params);

        [DllImport(DllName, CallingConvention = CallingConvention.Cdecl)]
        public static extern void SymCryptMlDsakeyFree(
            IntPtr key);

        [DllImport(DllName, CallingConvention = CallingConvention.Cdecl)]
        public static extern int SymCryptMlDsakeyGenerate(
            IntPtr key,
            uint flags);

        [DllImport(DllName, CallingConvention = CallingConvention.Cdecl)]
        public static extern int SymCryptMlDsaSign(
            IntPtr key,
            byte[] pbData,
            long cbData,
            byte[] pbOptional,
            long cbOptional,
            uint flags,
            byte[] pbSignature,
            long pcbSignature);

        [DllImport(DllName, CallingConvention = CallingConvention.Cdecl)]
        public static extern int SymCryptMlDsaVerify(
            IntPtr key,
            byte[] pbData,
            long cbData,
            byte[] pbOptional,
            long cbOptional,
            byte[] pbSignature,
            long pcbSignature,
            uint flags);

        [DllImport(DllName, CallingConvention = CallingConvention.Cdecl)]
        public static extern int SymCryptMlDsaSizeofKeyFormatFromParams(
                SYMCRYPT_MLDSA_PARAMS_ENUM mldsa_params,
                SYMCRYPT_MLDSAKEY_FORMAT mlDsakeyFormat,
                ref long pcbKeyFormat);

        [DllImport(DllName, CallingConvention = CallingConvention.Cdecl)]
        public static extern int SymCryptMlDsakeyGetValue(
            IntPtr key,
            byte[] pbDst,
            long cbDst,
            SYMCRYPT_MLDSAKEY_FORMAT mlDsakeyFormat,
            uint flags);

        [DllImport(DllName, CallingConvention = CallingConvention.Cdecl)]
        public static extern int SymCryptMlDsakeySetValue(
            byte[] pbKey,
            long cbKey,
            SYMCRYPT_MLDSAKEY_FORMAT mlDsaKeyFormat,
            uint flags,
            IntPtr ppkMlDsaHandle);

        [DllImport(DllName, CallingConvention = CallingConvention.Cdecl)]
        public static extern int SymCryptMlDsaSizeofSignatureFromParams(
            SYMCRYPT_MLDSA_PARAMS_ENUM mldsa_params,
            ref int pcbSignature);
        #endregion
    }

    internal static partial class SymCryptNative
    {
    }

    #region MLDSA
    [StructLayout(LayoutKind.Sequential)]
    internal struct SYMCRYPT_HMAC_SHA256_EXPANDED_KEY
    {
        [MarshalAs(UnmanagedType.ByValArray, SizeConst = 8)]
        public ulong[] innerState;

        [MarshalAs(UnmanagedType.ByValArray, SizeConst = 8)]
        public ulong[] outerState;

        public ulong magic;
    }

    [StructLayout(LayoutKind.Sequential)]
    internal struct SYMCRYPT_MLDSA_KEY
    {
        // Define the fields of the key structure as needed
    }

    [StructLayout(LayoutKind.Sequential)]
    internal struct SYMCRYPT_MLDSA_STRUCT
    {
        public int nBitsOfP;
        public int nBitsOfQ;
        public int nBitsOfSeed;
        public int fipsStandard;
    }

    internal enum SYMCRYPT_MLDSAKEY_FORMAT
    {
        NULL = 0,
        PRIVATE_SEED = 1,
        PRIVATE_KEY = 2,
        PUBLIC_KEY = 3
    }

    internal enum SYMCRYPT_MLDSA_PARAMS_ENUM
    {
        NULL = 0,
        MLDSA44 = 1,
        MLDSA65 = 2,
        MLDSA87 = 3,
    }
    #endregion

    #region RSA
    [StructLayout(LayoutKind.Sequential)]
    internal struct SYMCRYPT_RSA_PARAMS
    {
        public uint version;            // Version of the parameters structure
        public uint nBitsOfModulus;     // Number of bits in the modulus
        public uint nPrimes;            // Number of primes, 0 if object is only for public key
        public uint nPubExp;            // Number of public exponents (typically 1)
    }

    internal enum SYMCRYPT_NUMBER_FORMAT
    {
        LSB_FIRST = 1,
        MSB_FIRST = 2,
    }

    [StructLayout(LayoutKind.Sequential)]
    internal struct SYMCRYPT_RSAKEY
    {
        public uint fAlgorithmInfo; // Tracks which algorithms the key can be used in
        public uint cbTotalSize;    // Total size of the rsa key
        [MarshalAs(UnmanagedType.U1)]
        public bool hasPrivateKey;  // Set to true if there is private key information set
        public uint nSetBitsOfModulus;  // Bits of modulus specified during creation
        public uint nBitsOfModulus;     // Number of bits of the value of the modulus (not the object's size)
        public uint nDigitsOfModulus;   // Number of digits of the modulus object
        public uint nPubExp;            // Number of public exponents
        public uint nPrimes;            // Number of primes, can be 0 if the object only supports public keys

        [MarshalAs(UnmanagedType.ByValArray, SizeConst = 2)]
        public uint[] nBitsOfPrimes;    // Number of bits of the value of each prime
        [MarshalAs(UnmanagedType.ByValArray, SizeConst = 2)]
        public uint[] nDigitsOfPrimes;  // Number of digits of each prime object
        public uint nMaxDigitsOfPrimes; // Maximum number of digits in nDigitsOfPrimes

        [MarshalAs(UnmanagedType.ByValArray, SizeConst = 1)]
        public ulong[] au64PubExp;      // Array of public exponents

        [MarshalAs(UnmanagedType.ByValArray, SizeConst = 2)]
        public IntPtr[] pbPrimes;       // Pointers to the secret primes
        [MarshalAs(UnmanagedType.ByValArray, SizeConst = 2)]
        public IntPtr[] pbCrtInverses;  // Pointers to the CRT inverses of the primes
        [MarshalAs(UnmanagedType.ByValArray, SizeConst = 1)]
        public IntPtr[] pbPrivExps;     // Pointers to the corresponding private exponents
        [MarshalAs(UnmanagedType.ByValArray, SizeConst = 2)]
        public IntPtr[] pbCrtPrivExps;  // Pointers to the private exponents modulo each prime minus 1

        public IntPtr pmModulus;        // Pointer to the modulus N=p*q
        [MarshalAs(UnmanagedType.ByValArray, SizeConst = 2)]
        public IntPtr[] pmPrimes;       // Pointers to the secret primes
        [MarshalAs(UnmanagedType.ByValArray, SizeConst = 2)]
        public IntPtr[] peCrtInverses;  // Pointers to the CRT inverses of the primes
        [MarshalAs(UnmanagedType.ByValArray, SizeConst = 1)]
        public IntPtr[] piPrivExps;     // Pointers to the corresponding private exponents
        [MarshalAs(UnmanagedType.ByValArray, SizeConst = 2)]
        public IntPtr[] piCrtPrivExps;  // Pointers to the private exponents modulo each prime minus 1

        public UIntPtr magic;           // SYMCRYPT_MAGIC_FIELD

        // Note: The actual structure is followed by additional buffers in native code.
        // In C#, these are represented as pointers above.
    }

    #endregion

#pragma warning disable SYSLIB1054 // Use 'LibraryImportAttribute' instead of 'DllImportAttribute' to generate P/Invoke marshalling code at compile time
}
