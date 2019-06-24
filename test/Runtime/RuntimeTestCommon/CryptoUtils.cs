//-------------------------------------------------------------------------------------------------
// <copyright file="CryptoUtils.cs" company="Microsoft">
//     Copyright (c) Microsoft Corporation.  All rights reserved.
// </copyright>
//-------------------------------------------------------------------------------------------------

using System;
using System.Globalization;
using System.Security.Cryptography.X509Certificates;

namespace RuntimeTestCommon
{
    /// <summary>
    /// Crypto utilities.
    /// </summary>
    public static class CryptoUtils
    {
        /// <summary>
        /// Provides a way to obtain certificates from a specified certificate store.
        /// </summary>
        public static X509Certificate2 FindCertificate(StoreName storeName, StoreLocation storeLocation, string thumbprint)
        {
            X509Store x509Store = new X509Store(storeName, storeLocation);
            x509Store.Open(OpenFlags.ReadOnly);
            try
            {
                foreach (var cert in x509Store.Certificates)
                {
                    if (cert.Thumbprint.Equals(thumbprint, StringComparison.OrdinalIgnoreCase))
                    {
                        return cert;
                    }
                }

                throw new ArgumentException(string.Format(CultureInfo.InvariantCulture, LogMessages.PERF10000, thumbprint, storeName, storeLocation));
            }
            finally
            {
                if (x509Store != null)
                {
                    x509Store.Close();
                }
            }
        }

        /// <summary>
        /// Loads a <see cref="X509Certificate2" from the cert store, using the subject. />
        /// </summary>
        /// <param name="storeName">the store to use.</param>
        /// <param name="storeLocation">the location of the store.</param>
        /// <param name="subject">the subject name</param>
        /// <returns></returns>
        public static X509Certificate2 GetCertificateUsingSubject(StoreName storeName, StoreLocation storeLocation, string subject)
        {
            var x509Store = new X509Store(storeName, storeLocation);
            x509Store.Open(OpenFlags.ReadOnly);
            try
            {
                foreach (var cert in x509Store.Certificates)
                {
                    if (cert.Subject.Equals(subject, StringComparison.OrdinalIgnoreCase))
                        return cert;
                }

                throw new ArgumentException($"This sample communicates with AzureAD using a Certificate with subject: '{subject}'. SAL_SDK includes '<ROOT>\\src\\Certs\\{subject.Substring(subject.IndexOf('=') + 1)}.pfx' that needs to be imported into 'LocalComputer\\Personal' (password is: S2SWebSite).{1}'<ROOT>\\src\\ToolsAndScripts\\AddPfxToCertStore.ps1' can be used install certs.{1} Make sure to open the powershell window as an administrator.");
            }
            finally
            {
                if (x509Store != null)
                    x509Store.Close();
            }
        }
    }
}