//------------------------------------------------------------------------------
//
// Copyright (c) Microsoft Corporation.
// All rights reserved.
//
// This code is licensed under the MIT License.
//
// Permission is hereby granted, free of charge, to any person obtaining a copy
// of this software and associated documentation files(the "Software"), to deal
// in the Software without restriction, including without limitation the rights
// to use, copy, modify, merge, publish, distribute, sublicense, and / or sell
// copies of the Software, and to permit persons to whom the Software is
// furnished to do so, subject to the following conditions :
//
// The above copyright notice and this permission notice shall be included in
// all copies or substantial portions of the Software.
//
// THE SOFTWARE IS PROVIDED "AS IS", WITHOUT WARRANTY OF ANY KIND, EXPRESS OR
// IMPLIED, INCLUDING BUT NOT LIMITED TO THE WARRANTIES OF MERCHANTABILITY,
// FITNESS FOR A PARTICULAR PURPOSE AND NONINFRINGEMENT.IN NO EVENT SHALL THE
// AUTHORS OR COPYRIGHT HOLDERS BE LIABLE FOR ANY CLAIM, DAMAGES OR OTHER
// LIABILITY, WHETHER IN AN ACTION OF CONTRACT, TORT OR OTHERWISE, ARISING FROM,
// OUT OF OR IN CONNECTION WITH THE SOFTWARE OR THE USE OR OTHER DEALINGS IN
// THE SOFTWARE.
//
//------------------------------------------------------------------------------

using System;
using System.Security.Cryptography.X509Certificates;

namespace WcfUtilities
{
    public class CertificateUtilities
    {
        public static X509Certificate2 GetCertificate(StoreName name, StoreLocation location, X509FindType findType, object value)
        {
            X509Store store = null;
            X509Certificate2 certificate = null;
            try
            {
                store = new X509Store(name, location);
                store.Open(OpenFlags.ReadOnly);
                X509Certificate2Collection collection = store.Certificates.Find(findType, value, false);

                if (collection.Count == 0)
                    throw new InvalidProgramException($"Cert not found: StoreName: '{name}', StoreLocation: '{location}', X509FindType: '{findType}', findValue: '{value}'.");

                // we need this loop as some X509FindType will match multiple certs, so need to check for exact match and single
                foreach (var cert in collection)
                {
                    switch (findType)
                    {
                        case X509FindType.FindByThumbprint:
                            if (cert.Thumbprint.Equals(value as string, StringComparison.OrdinalIgnoreCase))
                            {
                                if (certificate == null)
                                    certificate = cert;
                                else
                                    throw new InvalidOperationException($"Mulitple certs found: StoreName: '{name}', StoreLocation: '{location}', X509FindType: '{findType}', findValue: '{value}'.");
                            }
                            break;

                        case X509FindType.FindBySubjectName:
                            if (cert.SubjectName.Equals(value))
                            {
                                if (certificate == null)
                                    certificate = cert;
                                else
                                    throw new InvalidOperationException($"Mulitple certs found: StoreName: '{name}', StoreLocation: '{location}', X509FindType: '{findType}', findValue: '{value}'.");
                            }
                            break;

                        case X509FindType.FindBySubjectDistinguishedName:
                            if (cert.SubjectName.Equals(value))
                            {
                                if (certificate == null)
                                    certificate = cert;
                                else
                                    throw new InvalidOperationException($"Mulitple certs found: StoreName: '{name}', StoreLocation: '{location}', X509FindType: '{findType}', findValue: '{value}'.");
                            }
                            break;

                        default:
                            throw new NotSupportedException($"X509FindType not supported: StoreName: '{name}', StoreLocation: '{location}', X509FindType: '{findType}', findValue: '{value}'.");
                    }
                }

                if (certificate == null)
                    throw new InvalidProgramException($"Cert not found: StoreName: '{name}', StoreLocation: '{location}', X509FindType: '{findType}', findValue: '{value}'.");

                Console.WriteLine($"Cert found: StoreName: '{name}', StoreLocation: '{location}', X509FindType: '{findType}', findValue: '{value}'.");
                return certificate;
            }
            finally
            {
                if (store != null)
                    store.Close();
            }
        }
    }
}
