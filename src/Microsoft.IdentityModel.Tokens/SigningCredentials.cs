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

using Microsoft.IdentityModel.Logging;

namespace Microsoft.IdentityModel.Tokens
{
    /// <summary>
    /// Defines the <see cref="SecurityKey"/>, algorithm and digest for digital signatures.
    /// </summary>
    public class SigningCredentials
    {
        /// <summary>
        /// Initializes a new instance of the <see cref="SigningCredentials"/> class.
        /// </summary>
        /// <param name="key"><see cref="SecurityKey"/>.</param>
        /// <param name="algorithm">The signature algorithm to apply.</param>
        /// <remarks>the 'digest method' if needed may be implied from the algorithm. For example <see cref="SecurityAlgorithms.HmacSha256Signature"/> implies Sha256.</remarks>
        public SigningCredentials(SecurityKey key, string algorithm)
        {
            if (key == null)
                throw LogHelper.LogArgumentNullException("key");

            if (string.IsNullOrEmpty(algorithm))
                throw LogHelper.LogArgumentNullException("algorithm");

            Algorithm = algorithm;
            Key = key;
        }

        /// <summary>
        /// Initializes a new instance of the <see cref="SigningCredentials"/> class.
        /// </summary>
        /// <param name="key"><see cref="SecurityKey"/>.</param>
        /// <param name="algorithm">The signature algorithm to apply.</param>
        /// <param name="digest">The digest algorithm to apply.</param>
        public SigningCredentials(SecurityKey key, string algorithm, string digest)
        {
            if (key == null)
                throw LogHelper.LogArgumentNullException("key");

            if (string.IsNullOrEmpty(algorithm))
                throw LogHelper.LogArgumentNullException("algorithm");

            Algorithm = algorithm;
            Key = key;

            // digest can be null
            if (!string.IsNullOrEmpty(digest))
                Digest = digest;
        }

        /// <summary>
        /// Gets the algorithm used for signatures.
        /// </summary>
        public string Algorithm
        {
            get;
            private set;
        }

        /// <summary>
        /// Gets the algorithm used for digests.
        /// </summary>
        public string Digest
        {
            get;
            private set;
        }

        /// <summary>
        /// Users can override the default <see cref="CryptoProviderFactory"/> with this property. This factory will be used for creating signature providers.
        /// </summary>
        /// <remarks>This will have precedence over <see cref="SecurityKey.CryptoProviderFactory"/></remarks>
        public CryptoProviderFactory CryptoProviderFactory { get; set; }

        /// <summary>
        /// Gets the <see cref="SecurityKey"/> which used for signature validation.
        /// </summary>
        public SecurityKey Key
        {
            get;
            private set;
        }

        /// <summary>
        /// Gets the key id associated with <see cref="SecurityKey"/>.
        /// </summary>
        public string Kid
        {
            get { return Key.KeyId; }
        }
    }
}
