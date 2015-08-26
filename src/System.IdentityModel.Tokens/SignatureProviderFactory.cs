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
using System.Globalization;

namespace System.IdentityModel.Tokens
{
    /// <summary>
    /// Creates <see cref="SignatureProvider"/>s by specifying a <see cref="SecurityKey"/> and algorithm.
    /// <para>Supports both <see cref="AsymmetricSecurityKey"/> and <see cref="SymmetricSecurityKey"/>.</para>
    /// </summary>
    public class SignatureProviderFactory
    {
        public static SignatureProviderFactory Default;

        /// <summary>
        /// This is the minimum <see cref="AsymmetricSecurityKey"/>.KeySize when creating signatures.
        /// </summary>
        public static readonly Int32 AbsoluteMinimumAsymmetricKeySizeInBitsForSigning = 2048;

        /// <summary>
        /// This is the minimum <see cref="AsymmetricSecurityKey"/>.KeySize when verifying signatures.
        /// </summary>
        public static readonly Int32 AbsoluteMinimumAsymmetricKeySizeInBitsForVerifying = 1024;

        /// <summary>
        /// This is the minimum <see cref="SymmetricSecurityKey"/>.KeySize when creating and verifying signatures.
        /// </summary>
        public static readonly Int32 AbsoluteMinimumSymmetricKeySizeInBits = 128;

        private static Int32 minimumAsymmetricKeySizeInBitsForSigning = AbsoluteMinimumAsymmetricKeySizeInBitsForSigning;
        private static Int32 minimumAsymmetricKeySizeInBitsForVerifying = AbsoluteMinimumAsymmetricKeySizeInBitsForVerifying;
        private static Int32 minimumSymmetricKeySizeInBits = AbsoluteMinimumSymmetricKeySizeInBits;

        static SignatureProviderFactory()
        {
            Default = new SignatureProviderFactory();
        }

        /// <summary>
        /// Gets or sets the minimum <see cref="SymmetricSecurityKey"/>.KeySize"/>.
        /// </summary>
        /// <exception cref="ArgumentOutOfRangeException">'value' is smaller than <see cref="AbsoluteMinimumSymmetricKeySizeInBits"/>.</exception>
        public static Int32 MinimumSymmetricKeySizeInBits
        {
            get
            {
                return minimumSymmetricKeySizeInBits;
            }

            set
            {
                if (value < AbsoluteMinimumSymmetricKeySizeInBits)
                {
                    throw new ArgumentOutOfRangeException("value", value, string.Format(CultureInfo.InvariantCulture, LogMessages.IDX10628, AbsoluteMinimumSymmetricKeySizeInBits));
                }

                minimumSymmetricKeySizeInBits = value;
            }
        }

        /// <summary>
        /// Gets or sets the minimum <see cref="AsymmetricSecurityKey"/>.KeySize for creating signatures.
        /// </summary>
        /// <exception cref="ArgumentOutOfRangeException">'value' is smaller than <see cref="AbsoluteMinimumAsymmetricKeySizeInBitsForSigning"/>.</exception>
        public static Int32 MinimumAsymmetricKeySizeInBitsForSigning
        {
            get
            {
                return minimumAsymmetricKeySizeInBitsForSigning;
            }

            set
            {
                if (value < AbsoluteMinimumAsymmetricKeySizeInBitsForSigning)
                {
                    throw new ArgumentOutOfRangeException("value", value, string.Format(CultureInfo.InvariantCulture, LogMessages.IDX10613, AbsoluteMinimumAsymmetricKeySizeInBitsForSigning));
                }

                minimumAsymmetricKeySizeInBitsForSigning = value;
            }
        }

        /// <summary>
        /// Gets or sets the minimum <see cref="AsymmetricSecurityKey"/>.KeySize for verifying signatures.
        /// <exception cref="ArgumentOutOfRangeException">'value' is smaller than <see cref="AbsoluteMinimumAsymmetricKeySizeInBitsForVerifying"/>.</exception>
        /// </summary>
        public static Int32 MinimumAsymmetricKeySizeInBitsForVerifying
        {
            get
            {
                return minimumAsymmetricKeySizeInBitsForVerifying;
            }

            set
            {
                if (value < AbsoluteMinimumAsymmetricKeySizeInBitsForVerifying)
                {
                    throw new ArgumentOutOfRangeException("value", value, string.Format(CultureInfo.InvariantCulture, LogMessages.IDX10627, AbsoluteMinimumAsymmetricKeySizeInBitsForVerifying));
                }

                minimumAsymmetricKeySizeInBitsForVerifying = value;
            }
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

        private static SignatureProvider CreateProvider(SecurityKey key, string algorithm, bool willCreateSignatures)
        {
            if (key == null)
            {
                throw new ArgumentNullException("key");
            }

            if (algorithm == null)
            {
                throw new ArgumentNullException("algorithm");
            }

            if (string.IsNullOrWhiteSpace(algorithm))
            {
                throw new ArgumentException(string.Format(CultureInfo.InvariantCulture, LogMessages.IDX10002, "algorithm "));
            }

            AsymmetricSecurityKey asymmetricKey = key as AsymmetricSecurityKey;
            if (asymmetricKey != null)
            {
                if (willCreateSignatures)
                {
                    if (asymmetricKey.KeySize < MinimumAsymmetricKeySizeInBitsForSigning)
                    {
                        throw new ArgumentOutOfRangeException("key.KeySize", asymmetricKey.KeySize, string.Format(CultureInfo.InvariantCulture, LogMessages.IDX10630, key.GetType(), MinimumAsymmetricKeySizeInBitsForSigning));
                    }
                }

                if (asymmetricKey.KeySize < MinimumAsymmetricKeySizeInBitsForVerifying)
                {
                    throw new ArgumentOutOfRangeException("key.KeySize", asymmetricKey.KeySize, string.Format(CultureInfo.InvariantCulture, LogMessages.IDX10631, key.GetType(), MinimumAsymmetricKeySizeInBitsForVerifying));
                }

                return new AsymmetricSignatureProvider(asymmetricKey, algorithm, willCreateSignatures);
            }

            SymmetricSecurityKey symmetricKey = key as SymmetricSecurityKey;
            if (symmetricKey != null)
            {
                if (symmetricKey.KeySize < MinimumSymmetricKeySizeInBits)
                {
                    throw new ArgumentOutOfRangeException("key.KeySize", key.KeySize, string.Format(CultureInfo.InvariantCulture, LogMessages.IDX10603, key.GetType(), MinimumSymmetricKeySizeInBits));
                }

                return new SymmetricSignatureProvider(symmetricKey, algorithm);
            }

            throw new ArgumentException(string.Format(CultureInfo.InvariantCulture, LogMessages.IDX10600, typeof(SignatureProvider).ToString(), typeof(SecurityKey), typeof(AsymmetricSecurityKey), typeof(SymmetricSecurityKey), key.GetType()));
        }
    }
}
