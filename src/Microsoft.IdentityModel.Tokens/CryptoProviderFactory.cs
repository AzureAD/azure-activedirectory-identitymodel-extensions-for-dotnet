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
using System.Collections.Generic;
using System.Security.Cryptography;
using Microsoft.IdentityModel.Logging;

namespace Microsoft.IdentityModel.Tokens
{
    /// <summary>
    /// Creates <see cref="SignatureProvider"/>s by specifying a <see cref="SecurityKey"/> and algorithm.
    /// <para>Supports both <see cref="AsymmetricSecurityKey"/> and <see cref="SymmetricSecurityKey"/>.</para>
    /// </summary>
    public class CryptoProviderFactory
    {
        /// <summary>
        /// Returns the default <see cref="CryptoProviderFactory"/> instance.
        /// </summary>
        public static CryptoProviderFactory Default;

        /// <summary>
        /// Extensibility point for custom crypto support
        /// </summary>
        /// <remarks>By default, if set, <see cref="ICryptoProvider.IsSupported(SecurityKey, string)"/> will be called before crypto operations.
        /// If true is returned, then this will be called for operations.</remarks>
        public static ICryptoProvider CustomCryptoProvider;

        /// <summary>
        /// Static constructor that initializes the default <see cref="CryptoProviderFactory"/>.
        /// </summary>
        static CryptoProviderFactory()
        {
            Default = new CryptoProviderFactory();
        }

        /// <summary>
        /// Default constructor for <see cref="CryptoProviderFactory"/>.
        /// </summary>
        public CryptoProviderFactory() { }

        /// <summary>
        /// Constructor that creates a deep copy of given <see cref="CryptoProviderFactory"/> object.
        /// </summary>
        /// <param name="factory"><see cref="CryptoProviderFactory"/> to copy from.</param>
        public CryptoProviderFactory(CryptoProviderFactory factory)
        {
            if (factory == null)
                throw LogHelper.LogArgumentNullException(nameof(factory));
        }

        /// <summary>
        /// Answers if an algorithm is supported
        /// </summary>
        /// <param name="key">the <see cref="SecurityKey"/></param>
        /// <param name="algorithm">the algorithm to use</param>
        /// <returns></returns>
        public virtual bool IsSupportedAlgorithm(SecurityKey key, string algorithm)
        {
            if (CustomCryptoProvider != null && CustomCryptoProvider.IsSupported(key, algorithm))
                return true;

            if (key as RsaSecurityKey != null)
                return IsRsaAlgorithmSupported(algorithm);

            if (key as X509SecurityKey != null)
                return IsRsaAlgorithmSupported(algorithm);

            JsonWebKey jsonWebKey = key as JsonWebKey;
            if (jsonWebKey != null)
            {
                if (jsonWebKey.Kty == JsonWebAlgorithmsKeyTypes.RSA)
                    return IsRsaAlgorithmSupported(algorithm);
                else if (jsonWebKey.Kty == JsonWebAlgorithmsKeyTypes.EllipticCurve)
                    return IsEcdsaAlgorithmSupported(algorithm);
                else if (jsonWebKey.Kty == JsonWebAlgorithmsKeyTypes.Octet)
                    return IsSymmetricAlgorithmSupported(algorithm);

                return false;
            }

            if (key as ECDsaSecurityKey != null)
                return IsEcdsaAlgorithmSupported(algorithm);

            if (key as SymmetricSecurityKey != null)
                return IsSymmetricAlgorithmSupported(algorithm);

            return false;
        }

        private bool IsEcdsaAlgorithmSupported(string algorithm)
        {
            switch (algorithm)
            {
                case SecurityAlgorithms.EcdsaSha256:
                case SecurityAlgorithms.EcdsaSha384:
                case SecurityAlgorithms.EcdsaSha512:
                case SecurityAlgorithms.EcdsaSha256Signature:
                case SecurityAlgorithms.EcdsaSha384Signature:
                case SecurityAlgorithms.EcdsaSha512Signature:
                    return true;
            }

            return false;
        }

        private bool IsRsaAlgorithmSupported(string algorithm)
        {
            switch (algorithm)
            {
                case SecurityAlgorithms.RsaSha256:
                case SecurityAlgorithms.RsaSha384:
                case SecurityAlgorithms.RsaSha512:
                case SecurityAlgorithms.RsaSha256Signature:
                case SecurityAlgorithms.RsaSha384Signature:
                case SecurityAlgorithms.RsaSha512Signature:
                    return true;
            }

            return false;
        }

        private bool IsSymmetricAlgorithmSupported(string algorithm)
        {
            switch (algorithm)
            {
                case SecurityAlgorithms.HmacSha256Signature:
                case SecurityAlgorithms.HmacSha384Signature:
                case SecurityAlgorithms.HmacSha512Signature:
                case SecurityAlgorithms.HmacSha256:
                case SecurityAlgorithms.HmacSha384:
                case SecurityAlgorithms.HmacSha512:
                    return true;
            }

            return false;
        }

        /// <summary>
        /// Creates a <see cref="SignatureProvider"/> that supports the <see cref="SecurityKey"/> and algorithm.
        /// </summary>
        /// <param name="key">The <see cref="SecurityKey"/> to use for signing.</param>
        /// <param name="algorithm">The algorithm to use for signing.</param>
        /// <exception cref="ArgumentNullException">'key' is null.</exception>
        /// <exception cref="ArgumentNullException">'algorithm' is null.</exception>
        /// <exception cref="ArgumentException">'algorithm' contains only whitespace.</exception>
        /// <exception cref="ArgumentOutOfRangeException"><see cref="AsymmetricSecurityKey"/>' is too small.</exception>
        /// <exception cref="ArgumentOutOfRangeException"><see cref="SymmetricSecurityKey"/> is too small.</exception>
        /// <exception cref="ArgumentException"><see cref="SecurityKey"/> is not a <see cref="AsymmetricSecurityKey"/> or a <see cref="SymmetricSecurityKey"/>.</exception>
        /// <remarks>
        /// AsymmetricSignatureProviders require access to a PrivateKey for Signing.
        /// </remarks>
        public virtual SignatureProvider CreateForSigning(SecurityKey key, string algorithm)
        {
            return CreateProvider(key, algorithm, true);
        }

        /// <summary>
        /// Returns a <see cref="SignatureProvider"/> instance supports the <see cref="SecurityKey"/> and algorithm.
        /// </summary>
        /// <param name="key">The <see cref="SecurityKey"/> to use for signing.</param>
        /// <param name="algorithm">The algorithm to use for verifying.</param>
        /// <exception cref="ArgumentNullException">'key' is null.</exception>
        /// <exception cref="ArgumentNullException">'algorithm' is null or whitespace.</exception>
        /// <exception cref="ArgumentOutOfRangeException"><see cref="AsymmetricSecurityKey"/> is too small.</exception>
        /// <exception cref="ArgumentOutOfRangeException"><see cref="SymmetricSecurityKey"/> is too small.</exception>
        /// <exception cref="ArgumentException"><see cref="SecurityKey"/>' is not a <see cref="AsymmetricSecurityKey"/> or a <see cref="SymmetricSecurityKey"/>.</exception>
        public virtual SignatureProvider CreateForVerifying(SecurityKey key, string algorithm)
        {
            return CreateProvider(key, algorithm, false);
        }

        /// <summary>
        /// When finished with a <see cref="SignatureProvider"/> call this method for cleanup. The default behavior is to call <see cref="SignatureProvider.Dispose(bool)"/>
        /// </summary>
        /// <param name="signatureProvider"><see cref="SignatureProvider"/> to be released.</param>
        public virtual void ReleaseSignatureProvider(SignatureProvider signatureProvider)
        {
            if (signatureProvider != null)
                signatureProvider.Dispose();
        }

        private SignatureProvider CreateProvider(SecurityKey key, string algorithm, bool willCreateSignatures)
        {
            if (key == null)
                throw LogHelper.LogArgumentNullException(nameof(key));

            if (string.IsNullOrWhiteSpace(algorithm))
                throw LogHelper.LogArgumentNullException(nameof(algorithm));

            AsymmetricSecurityKey asymmetricKey = key as AsymmetricSecurityKey;
            if (asymmetricKey != null)
                return new AsymmetricSignatureProvider(asymmetricKey, algorithm, willCreateSignatures, CustomCryptoProvider);

            SymmetricSecurityKey symmetricKey = key as SymmetricSecurityKey;
            if (symmetricKey != null)
                return new SymmetricSignatureProvider(symmetricKey, algorithm, CustomCryptoProvider);

            JsonWebKey jsonWebKey = key as JsonWebKey;
            if (jsonWebKey != null)
            {
                if (jsonWebKey.Kty != null)
                {
                    if (jsonWebKey.Kty == JsonWebAlgorithmsKeyTypes.RSA || jsonWebKey.Kty == JsonWebAlgorithmsKeyTypes.EllipticCurve)
                        return new AsymmetricSignatureProvider(key, algorithm, willCreateSignatures, CustomCryptoProvider);

                    if (jsonWebKey.Kty == JsonWebAlgorithmsKeyTypes.Octet)
                        return new SymmetricSignatureProvider(key, algorithm);
                }
            }

            throw LogHelper.LogException<ArgumentException>(LogMessages.IDX10600, typeof(SignatureProvider), typeof(SecurityKey), typeof(AsymmetricSecurityKey), typeof(SymmetricSecurityKey), key.GetType());
        }
    }
}
