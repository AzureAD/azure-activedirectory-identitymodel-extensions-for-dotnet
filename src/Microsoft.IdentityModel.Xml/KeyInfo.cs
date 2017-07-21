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
using Microsoft.IdentityModel.Tokens;

namespace Microsoft.IdentityModel.Xml
{
    /// <summary>
    /// Represents a XmlDsig KeyInfo element as per:  https://www.w3.org/TR/2001/PR-xmldsig-core-20010820/#sec-KeyInfo
    /// </summary>
    /// <remarks>Only a single 'X509Certificate' is supported. Multiples that include intermediate and root certs are not supported.</remarks>
    public class KeyInfo
    {
        // TODO - IssuerSerial needs to have a structure as 'IssuerName' and 'SerialNumber'
        /// <summary>
        /// Initializes an instance of <see cref="KeyInfo"/>.
        /// </summary>
        public KeyInfo()
        {
        }

        /// <summary>
        /// Initializes an instance of <see cref="KeyInfo"/>.
        /// </summary>
        /// <param name="certificate">the <see cref="X509Certificate2"/>to populate the X509Data.</param>
        public KeyInfo(X509Certificate2 certificate)
        {
            CertificateData = Convert.ToBase64String(certificate.RawData);
            Kid = certificate.Thumbprint;
        }

        /// <summary>
        /// Initializes an instance of <see cref="KeyInfo"/>.
        /// </summary>
        /// <param name="key">the <see cref="SecurityKey"/>to populate the <see cref="KeyInfo"/>.</param>
        public KeyInfo(SecurityKey key)
        {
            if (key is X509SecurityKey x509Key)
            {
                CertificateData = Convert.ToBase64String(x509Key.Certificate.RawData);
                Kid = x509Key.Certificate.Thumbprint;
            }
        }

        /// <summary>
        /// Get or sets the 'X509CertificateData' value
        /// </summary>
        public string CertificateData
        {
            get;
            set;
        }

        /// <summary>
        /// Gets or sets the IssuerName that is part of a 'X509IssuerSerial'
        /// </summary>
        public string IssuerName
        {
            get;
            set;
        }

        /// <summary>
        /// Gets or sets the a kid that reflects the type of 'X509Data'
        /// For multiple X509Data the last one will be used
        /// </summary>
        public string Kid
        {
            get;
            set;
        }

        /// <summary>
        /// Gets or sets the Uri associated with the RetrievalMethod
        /// </summary>
        public string RetrievalMethodUri
        {
            get;
            set;
        }

        /// <summary>
        /// Get or sets the SerialNumber that is part of a 'X509IssuerSerial'
        /// </summary>
        public string SerialNumber
        {
            get;
            set;
        }

        /// <summary>
        /// Gets or sets the 'X509SKI' value
        /// </summary>
        public string SKI
        {
            get;
            set;
        }

        /// <summary>
        /// Get or sets the 'X509SubjectName' value
        /// </summary>
        public string SubjectName
        {
            get;
            set;
        }
    }
}
