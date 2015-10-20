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
using System.Diagnostics.Tracing;
using System.Globalization;
using Microsoft.IdentityModel.Logging;

namespace System.IdentityModel.Tokens
{
    /// <summary>
    /// Creates <see cref="SignatureProvider"/>s by specifying a <see cref="SecurityKey"/> and algorithm.
    /// <para>Supports both <see cref="AsymmetricSecurityKey"/> and <see cref="SymmetricSecurityKey"/>.</para>
    /// </summary>
    public class SignatureProviderFactory
    {
        public static SignatureProviderFactory Default;

        static SignatureProviderFactory()
        {
            Default = new SignatureProviderFactory();
        }

        /// <summary>
        /// Creates a <see cref="SignatureProvider"/> that supports the <see cref="SecurityKey"/> and algorithm.
        /// </summary>
        /// <param name="key">
        /// The <see cref="SecurityKey"/> to use for signing.
        /// </param>
        /// <param name="algorithm">
        /// The algorithm to use for signing.
        /// </param>
        /// <exception cref="ArgumentNullException">
        /// 'key' is null.
        /// </exception>
        /// <exception cref="ArgumentNullException">
        /// 'algorithm' is null.
        /// </exception>
        /// <exception cref="ArgumentException">
        /// 'algorithm' contains only whitespace.
        /// </exception>
        /// <exception cref="ArgumentOutOfRangeException">
        /// '<see cref="AsymmetricSecurityKey"/>' is smaller than <see cref="MinimumAsymmetricKeySizeInBitsForSigning"/>.
        /// </exception>
        /// <exception cref="ArgumentOutOfRangeException">
        /// '<see cref="SymmetricSecurityKey"/>' is smaller than <see cref="MinimumSymmetricKeySizeInBits"/>.
        /// </exception>
        /// <exception cref="ArgumentException">
        /// '<see cref="SecurityKey"/>' is not a <see cref="AsymmetricSecurityKey"/> or a <see cref="SymmetricSecurityKey"/>.
        /// </exception>
        /// <remarks>
        /// AsymmetricSignatureProviders require access to a PrivateKey for Signing.
        /// </remarks>
        /// <returns>
        /// The <see cref="SignatureProvider"/>.
        /// </returns>
        public virtual SignatureProvider CreateForSigning(SecurityKey key, string algorithm)
        {
            return CreateProvider(key, algorithm, true);
        }

        /// <summary>
        /// Returns a <see cref="SignatureProvider"/> instance supports the <see cref="SecurityKey"/> and algorithm.
        /// </summary>
        /// <param name="key">
        /// The <see cref="SecurityKey"/> to use for signing.
        /// </param>
        /// <param name="algorithm">
        /// The algorithm to use for signing.
        /// </param>
        /// <exception cref="ArgumentNullException">
        /// 'key' is null.
        /// </exception>
        /// <exception cref="ArgumentNullException">
        /// 'algorithm' is null.
        /// </exception>
        /// <exception cref="ArgumentException">
        /// 'algorithm' contains only whitespace.
        /// </exception>
        /// <exception cref="ArgumentOutOfRangeException">
        /// '<see cref="AsymmetricSecurityKey"/>' is smaller than <see cref="MinimumAsymmetricKeySizeInBitsForVerifying"/>.
        /// </exception>
        /// <exception cref="ArgumentOutOfRangeException">
        /// '<see cref="SymmetricSecurityKey"/>' is smaller than <see cref="MinimumSymmetricKeySizeInBits"/>.
        /// </exception>
        /// <exception cref="ArgumentException">
        /// '<see cref="SecurityKey"/>' is not a <see cref="AsymmetricSecurityKey"/> or a <see cref="SymmetricSecurityKey"/>.
        /// </exception>
        /// <returns>
        /// The <see cref="SignatureProvider"/>.
        /// </returns>
        public virtual SignatureProvider CreateForVerifying(SecurityKey key, string algorithm)
        {
            return CreateProvider(key, algorithm, false);
        }

        /// <summary>
        /// When finished with a <see cref="SignatureProvider"/> call this method for cleanup. The default behavior is to call <see cref="SignatureProvider.Dispose(bool)"/>
        /// </summary>
        /// <param name="signatureProvider"><see cref="SignatureProvider"/> to be released.</param>
        public virtual void ReleaseProvider(SignatureProvider signatureProvider)
        {
            if (signatureProvider != null)
            {
                signatureProvider.Dispose();
            }
        }

        private SignatureProvider CreateProvider(SecurityKey key, string algorithm, bool willCreateSignatures)
        {
            if (key == null)
            {
                LogHelper.Throw(string.Format(CultureInfo.InvariantCulture, LogMessages.IDX10000, "CreateProvider.key"), typeof(ArgumentNullException), EventLevel.Verbose);
            }

            if (algorithm == null)
            {
                LogHelper.Throw(string.Format(CultureInfo.InvariantCulture, LogMessages.IDX10000, "CreateProvider.algorithm"), typeof(ArgumentNullException), EventLevel.Verbose);
            }

            if (string.IsNullOrWhiteSpace(algorithm))
            {
                throw new ArgumentException(string.Format(CultureInfo.InvariantCulture, LogMessages.IDX10002, "algorithm "));
            }

            AsymmetricSecurityKey asymmetricKey = key as AsymmetricSecurityKey;
            if (asymmetricKey != null)
            {
                return new AsymmetricSignatureProvider(asymmetricKey, algorithm, willCreateSignatures);
            }

            SymmetricSecurityKey symmetricKey = key as SymmetricSecurityKey;
            if (symmetricKey != null)
            {
                return new SymmetricSignatureProvider(symmetricKey, algorithm);
            }

            throw new ArgumentException(string.Format(CultureInfo.InvariantCulture, LogMessages.IDX10600, typeof(SignatureProvider).ToString(), typeof(SecurityKey), typeof(AsymmetricSecurityKey), typeof(SymmetricSecurityKey), key.GetType()));
        }
    }
}
