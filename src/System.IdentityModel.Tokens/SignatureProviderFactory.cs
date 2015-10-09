//-----------------------------------------------------------------------
// Copyright (c) Microsoft Open Technologies, Inc.
// All Rights Reserved
// Apache License 2.0
//
// Licensed under the Apache License, Version 2.0 (the "License");
// you may not use this file except in compliance with the License.
// You may obtain a copy of the License at
// 
// http://www.apache.org/licenses/LICENSE-2.0
// 
// Unless required by applicable law or agreed to in writing, software
// distributed under the License is distributed on an "AS IS" BASIS,
// WITHOUT WARRANTIES OR CONDITIONS OF ANY KIND, either express or implied.
// See the License for the specific language governing permissions and
// limitations under the License.
//-----------------------------------------------------------------------

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
