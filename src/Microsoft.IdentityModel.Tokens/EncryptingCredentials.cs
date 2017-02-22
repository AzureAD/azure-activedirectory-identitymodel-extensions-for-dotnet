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
    /// A wrapper class for properties that are used for token encryption.
    /// </summary>
    public class EncryptingCredentials
    {
        /// <summary>
        /// Initializes a new instance of the <see cref="EncryptingCredentials"/> class.
        /// </summary>
        /// <param name="key"><see cref="SecurityKey"/></param>
        /// <param name="alg">The key encryption algorithm to apply.</param>
        /// <param name="enc">The encryption algorithm to apply.</param>
        public EncryptingCredentials(SecurityKey key, string alg, string enc)
        {
            if (key == null)
                throw LogHelper.LogArgumentNullException(nameof(key));

            if (string.IsNullOrWhiteSpace(alg))
                throw LogHelper.LogArgumentNullException(nameof(alg));

            if (string.IsNullOrWhiteSpace(enc))
                throw LogHelper.LogArgumentNullException(nameof(enc));

            Alg = alg;
            Enc = enc;
            Key = key;
        }

        /// <summary>
        /// Gets the algorithm which used for token encryption.
        /// </summary>
        public string Alg
        {
            get;
            private set;
        }

        /// <summary>
        /// Gets the algorithm which used for token encryption.
        /// </summary>
        public string Enc
        {
            get;
            private set;
        }

        /// <summary>
        /// Users can override the default <see cref="CryptoProviderFactory"/> with this property. This factory will be used for creating encryition providers.
        /// </summary>
        public CryptoProviderFactory CryptoProviderFactory { get; set; }

        /// <summary>
        /// Gets the <see cref="SecurityKey"/> which used for signature valdiation.
        /// </summary>
        public SecurityKey Key
        {
            get;
            private set;
        }
    }
}
