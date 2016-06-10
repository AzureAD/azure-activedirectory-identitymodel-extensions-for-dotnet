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

using System.Security.Cryptography;

namespace Microsoft.IdentityModel.Tokens
{
    /// <summary>
    /// Crypto operations
    /// </summary>
    public interface ICryptoProvider
    {
        /// <summary>
        /// Called to determin if &lt;key, algorithm&gt; is supported.
        /// </summary>
        /// <param name="key">the <see cref="SecurityKey"/> to use.</param>
        /// <param name="algorithm">the algorithm to apply.</param>
        /// <returns>true if supported</returns>
        bool IsSupported(SecurityKey key, string algorithm);

        /// <summary>
        /// returns a <see cref="HashAlgorithm>"/> for a signature algorithm
        /// </summary>
        /// <param name="signatureAlgorithm">the signature algorithm.</param>
        HashAlgorithm ResolveHashAlgorithmFromSignatureAlgorithm(string signatureAlgorithm);

        /// <summary>
        /// returns a <see cref="SignatureProvider"/> that supports a <see cref="SecurityKey"/> algorithm pair.
        /// </summary>
        /// <param name="key">the <see cref="SecurityKey"/> to use.</param>
        /// <param name="algorithm">the algorithm to apply.</param>
        SignatureProvider ResolveSignatureProvider(SecurityKey key, string algorithm);
    }
}
