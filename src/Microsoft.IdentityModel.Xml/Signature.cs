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
using System.IO;
using System.Security.Cryptography;
using Microsoft.IdentityModel.Tokens;
using static Microsoft.IdentityModel.Logging.LogHelper;

namespace Microsoft.IdentityModel.Xml
{
    /// <summary>
    /// Represents a XmlDsig Signature element as per: https://www.w3.org/TR/2001/PR-xmldsig-core-20010820/#sec-Signature
    /// </summary>
    public class Signature : DSigElement
    {
        private string _signatureValue;
        private SignedInfo _signedInfo;

        /// <summary>
        /// Initializes a <see cref="Signature"/> instance.
        /// </summary>
        public Signature()
        {
        }

        /// <summary>
        /// Gets or set the KeyInfo
        /// </summary>
        public KeyInfo KeyInfo
        {
            get;
            set;
        }

        /// <summary>
        /// Gets or sets the SignatureValue
        /// </summary>
        /// <exception cref="ArgumentNullException">if 'value' is null or empty.</exception>
        public string SignatureValue
        {
            get => _signatureValue;
            set => _signatureValue = string.IsNullOrEmpty(value) ? throw LogArgumentNullException(nameof(value)) : value;
        }

        /// <summary>
        /// Gets or sets the <see cref="SignedInfo"/>.
        /// </summary>
        /// <exception cref="ArgumentNullException">if 'value' is null.</exception>
        public SignedInfo SignedInfo
        {
            get => _signedInfo;
            set => _signedInfo = value ?? throw LogArgumentNullException(nameof(value));
        }

        /// <summary>
        /// 
        /// </summary>
        /// <param name="key"></param>
        public void Verify(SecurityKey key)
        {
            if (key == null)
                throw LogArgumentNullException(nameof(key));

            var signatureProvider = key.CryptoProviderFactory.CreateForVerifying(key, SignedInfo.SignatureMethod);
            if (signatureProvider == null)
                throw LogExceptionMessage(new XmlValidationException(FormatInvariant(LogMessages.IDX21203, key.CryptoProviderFactory, key, SignedInfo.SignatureMethod)));

            try
            {
                using (var memoryStream = new MemoryStream())
                {
                    SignedInfo.GetCanonicalBytes(memoryStream);

                    if (!signatureProvider.Verify(SignedInfo.CanonicalStream.ToArray(), Convert.FromBase64String(SignatureValue)))
                        throw LogExceptionMessage(new CryptographicException(LogMessages.IDX21200));
                }
            }
            finally
            {
                if (signatureProvider != null)
                    key.CryptoProviderFactory.ReleaseSignatureProvider(signatureProvider);
            }

            SignedInfo.Verify(key.CryptoProviderFactory);
        }
    }
}
