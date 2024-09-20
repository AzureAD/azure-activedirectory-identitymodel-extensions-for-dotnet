// Copyright (c) Microsoft Corporation. All rights reserved.
// Licensed under the MIT License.

using System.Security.Cryptography.X509Certificates;

namespace Microsoft.IdentityModel.Tokens
{
    /// <summary>
    /// Helper class to load X509Certificate2 from byte array.
    /// </summary>
    internal class CertificateHelper
    {
        public static X509Certificate2 Load(byte[] data)
        {
#if NET9_0_OR_GREATER
            return X509CertificateLoader.LoadCertificate(data);
#else
            return new X509Certificate2(data);
#endif
        }
    }
}
