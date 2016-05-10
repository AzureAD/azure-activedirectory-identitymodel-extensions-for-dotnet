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
using Microsoft.IdentityModel.Logging;

namespace Microsoft.IdentityModel.Tokens
{
    /// <summary>
    /// Base class for Security Key.
    /// </summary>
    public abstract class SecurityKey
    {
        private CryptoProviderFactory _cryptoProviderFactory = CryptoProviderFactory.Default;

        /// <summary>
        /// This must be overridden to get the size of this <see cref="SecurityKey"/>.
        /// </summary>
        public abstract int KeySize { get; }

        /// <summary>
        /// Gets the key id of this <see cref="SecurityKey"/>.
        /// </summary>
        public string KeyId { get; set; }


        /// <summary>
        /// Creates a <see cref="SignatureProvider"/> instance that supports the algorithm.
        /// </summary>
        /// <param name="algorithm">The algorithm to use for signing.</param>
        public SignatureProvider GetSignatureProviderForSigning(string algorithm)
        {
            return GetSignatureProvider(algorithm, false);
        }

        /// <summary>
        /// Creates a <see cref="SignatureProvider"/> instance that supports the algorithm.
        /// </summary>
        /// <param name="algorithm">The algorithm to use for verifying.</param>
        public SignatureProvider GetSignatureProviderForVerifying(string algorithm)
        {
            return GetSignatureProvider(algorithm, true);
        }

        /// <summary>
        /// This must be overridden to returns a <see cref="SignatureProvider"/> instance that will provide signatures support for this key and algorithm.
        /// </summary>
        /// <param name="algorithm">The algorithm to use for verifying/signing.</param>
        /// <param name="verifyOnly">This value is indicates if the <see cref="SignatureProvider"/> will be used to create or verify signatures.
        /// If verifyOnly is false, then the private key is required.</param>
        public abstract SignatureProvider GetSignatureProvider(string algorithm, bool verifyOnly);

        /// <summary>
        /// This must be overridden to specify whether this SecurityKey supports the algorithm.
        /// </summary>
        /// <param name="algorithm">The crypto algorithm to use.</param>
        /// <returns>true if this supports the algorithm; otherwise, false.</returns>
        public abstract bool IsSupportedAlgorithm(string algorithm);

        /// <summary>
        /// Gets or sets <see cref="Microsoft.IdentityModel.Tokens.CryptoProviderFactory"/>.
        /// </summary>
        public CryptoProviderFactory CryptoProviderFactory
        {
            get
            {
                return _cryptoProviderFactory;
            }
            set
            {
                if (value == null)
                {
                    throw LogHelper.LogArgumentNullException("value");
                };

                _cryptoProviderFactory = value;
            }
        }
    }
}
