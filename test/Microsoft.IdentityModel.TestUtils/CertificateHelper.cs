// Copyright (c) Microsoft Corporation. All rights reserved.
// Licensed under the MIT License.

using System.Security;
using System.Security.Cryptography.X509Certificates;

namespace Microsoft.IdentityModel.TestUtils
{
    /// <summary>
    /// Helper class to load X509Certificate2 from byte array.
    /// </summary>
    public class CertificateHelper
    {
        public static X509Certificate2 LoadX509Certificate(byte[] data)
        {
#if NET9_0_OR_GREATER
            return X509CertificateLoader.LoadCertificate(data);
#else
            return new X509Certificate2(data);
#endif
        }

        /// <summary>
        /// Construct a X509Certificate2 from a byte array, a password, and a flag.
        /// </summary>
        /// <param name="data"></param>
        /// <param name="password"></param>
        /// <param name="flag"></param>
        /// <returns></returns>
        public static X509Certificate2 LoadX509Certificate(byte[] data, SecureString password, X509KeyStorageFlags flag)
        {
#pragma warning disable SYSLIB0057 // X509CertificateLoader does not have the correct overloads for this constructor
            return new X509Certificate2(data, password, flag);
#pragma warning restore SYSLIB0057 // issue tracking this warning https://github.com/AzureAD/azure-activedirectory-identitymodel-extensions-for-dotnet/issues/2833
        }

        /// <summary>
        /// Construct a X509Certificate2 from a byte array and a password.
        /// </summary>
        /// <param name="data"></param>
        /// <param name="password"></param>
        /// <returns></returns>
        public static X509Certificate2 LoadX509Certificate(byte[] data, SecureString password)
        {
#pragma warning disable SYSLIB0057 // X509CertificateLoader does not have the correct overloads for this constructor
            return new X509Certificate2(data, password);
#pragma warning restore SYSLIB0057 // issue tracking this warning https://github.com/AzureAD/azure-activedirectory-identitymodel-extensions-for-dotnet/issues/2833
        }
    }
}
