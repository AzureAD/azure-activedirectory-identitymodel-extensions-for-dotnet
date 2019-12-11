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
using Microsoft.IdentityModel.Json;

namespace Microsoft.IdentityModel.Tokens
{
    /// <summary>
    /// Base class for Security Key.
    /// </summary>
    public abstract class SecurityKey
    {
        private CryptoProviderFactory _cryptoProviderFactory;

        internal SecurityKey(SecurityKey key)
        {
            _cryptoProviderFactory = key._cryptoProviderFactory;
            KeyId = key.KeyId;
        }

        /// <summary>
        /// Default constructor
        /// </summary>
        public SecurityKey()
        {
            _cryptoProviderFactory = CryptoProviderFactory.Default;
        }

        [JsonIgnore]
        internal string InternalId { get; } = Guid.NewGuid().ToString();

        /// <summary>
        /// This must be overridden to get the size of this <see cref="SecurityKey"/>.
        /// </summary>
        public abstract int KeySize { get; }

        /// <summary>
        /// Gets the key id of this <see cref="SecurityKey"/>.
        /// </summary>
        [JsonIgnore]
        public virtual string KeyId { get; set; }

        /// <summary>
        /// Gets or sets <see cref="Microsoft.IdentityModel.Tokens.CryptoProviderFactory"/>.
        /// </summary>
        [JsonIgnore]
        public CryptoProviderFactory CryptoProviderFactory
        {
            get
            {
                return _cryptoProviderFactory;
            }
            set
            {
                _cryptoProviderFactory = value ?? throw LogHelper.LogArgumentNullException(nameof(value));
            }
        }

        /// <summary>
        /// Returns the formatted string: GetType(), KeyId: 'value', InternalId: 'value'.
        /// </summary>
        /// <returns>string</returns>
        public override string ToString()
        {
            return $"{GetType()}, KeyId: '{KeyId}', InternalId: '{InternalId}'.";
        }

        /// <summary>
        /// Computes a sha256 hash over the <see cref="SecurityKey"/>.
        /// </summary>
        /// <returns>A JWK thumbprint.</returns>
        /// <remarks>https://tools.ietf.org/html/rfc7638</remarks>
        public virtual byte[] ComputeJwkThumbprint()
        {
            throw LogHelper.LogExceptionMessage(new NotSupportedException(LogHelper.FormatInvariant(LogMessages.IDX10710)));
        }
    }
}
