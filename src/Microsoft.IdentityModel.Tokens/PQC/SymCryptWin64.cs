// Copyright (c) Microsoft Corporation. All rights reserved.
// Licensed under the MIT License.

using System.Runtime.InteropServices;

namespace Microsoft.IdentityModel.Tokens
{
    /// <summary>
    /// This class provides P/Invoke methods structures and errors for calling into SymCrypt.dll.
    /// The plan is to expand to include RSA and ECC for comparisons .net.
    /// </summary>
    internal static class SymCryptWin64
    {
#pragma warning disable SYSLIB1054 // Use 'LibraryImportAttribute' instead of 'DllImportAttribute' to generate P/Invoke marshalling code at compile time

        // The placement of the DLL is important. The DLL is in the PQC folder.
        // This dll is from: https://github.com/microsoft/SymCrypt/releases
        private const string DllName = "PQC/SymCryptWin64.dll";

        [DllImport(DllName, CallingConvention = CallingConvention.Cdecl)]
        public static extern int CreateRsaKeyAndSign(
            byte[] data,
            long dataLength,
            ref byte[] signature,
            ref long signatureLength);
    }
#pragma warning disable SYSLIB1054 // Use 'LibraryImportAttribute' instead of 'DllImportAttribute' to generate P/Invoke marshalling code at compile time
}
