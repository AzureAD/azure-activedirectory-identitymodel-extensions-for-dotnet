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
using System.Security.Cryptography;
using Microsoft.IdentityModel.Logging;
using System.Collections.Generic;

namespace Microsoft.IdentityModel.Tokens
{
    /// <summary>
    /// Creates <see cref="SignatureProvider"/>s by specifying a <see cref="SecurityKey"/> and algorithm.
    /// <para>Supports both <see cref="AsymmetricSecurityKey"/> and <see cref="SymmetricSecurityKey"/>.</para>
    /// </summary>
    public class CryptoProviderFactory
    {
        private static CryptoProviderFactory _default;
        public static readonly HashSet<string> DefaultkeyWrapAlgorithm = new HashSet<string>()
        {
            { SecurityAlgorithms.Aes128CbcHmacSha256 },
            { SecurityAlgorithms.Aes256CbcHmacSha512 }
        };

        public static readonly HashSet<string> DefaultContentEncryptAlgorithm = new HashSet<string>()
        {
            { SecurityAlgorithms.RsaPKCS1 },
            { SecurityAlgorithms.RsaOAEP },
            { SecurityAlgorithms.Aes128KW }
        };

        private HashSet<string> _keyWrapAlgorithm;
        private HashSet<string> _contentEncryptAlgorithm;

        /// <summary>
        /// Returns the default <see cref="CryptoProviderFactory"/> instance.
        /// </summary>
        public static CryptoProviderFactory Default
        {
            get { return _default; }
            set
            {
                if (value == null)
                    throw LogHelper.LogArgumentNullException("value");

                _default = value;
            }
        }

        /// <summary>
        /// Extensibility point for custom crypto support application wide.
        /// </summary>
        /// <remarks>By default, if set, <see cref="ICryptoProvider.IsSupportedAlgorithm(string, object[])"/> will be called before crypto operations.
        /// If true is returned, then this will be called for operations.</remarks>
        public ICryptoProvider CustomCryptoProvider { get; set; }

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
        public CryptoProviderFactory()
        {
            _keyWrapAlgorithm = new HashSet<string>(DefaultkeyWrapAlgorithm);
            _contentEncryptAlgorithm = new HashSet<string>(DefaultContentEncryptAlgorithm);
        }

        /// <summary>
        /// Constructor that creates a deep copy of given <see cref="CryptoProviderFactory"/> object.
        /// </summary>
        /// <param name="other"><see cref="CryptoProviderFactory"/> to copy from.</param>
        public CryptoProviderFactory(CryptoProviderFactory other)
        {
            if (other == null)
                throw LogHelper.LogArgumentNullException(nameof(other));

            CustomCryptoProvider = other.CustomCryptoProvider;
        }

        /// <summary>
        /// Answers if an algorithm is supported
        /// </summary>
        /// <param name="algorithm">the name of the crypto algorithm</param>
        /// <returns></returns>
        public virtual bool IsSupportedAlgorithm(string algorithm)
        {
            if (CustomCryptoProvider != null && CustomCryptoProvider.IsSupportedAlgorithm(algorithm))
                return true;

            return IsSupportedHashAlgorithm(algorithm);
        }

        /// <summary>
        /// Answers if an algorithm is supported
        /// </summary>
        /// <param name="algorithm">the algorithm to use</param>
        /// <param name="key">the <see cref="SecurityKey"/></param>
        /// <returns></returns>
        public virtual bool IsSupportedAlgorithm(string algorithm, SecurityKey key)
        {
            if (CustomCryptoProvider != null && CustomCryptoProvider.IsSupportedAlgorithm(algorithm, key))
                return true;

            if (key as RsaSecurityKey != null)
                return IsRsaAlgorithmSupported(algorithm);

            var x509Key = key as X509SecurityKey;
            if (x509Key != null)
            {
#if NETSTANDARD1_4
                if (x509Key.PublicKey as RSA == null)
                    return false;
#else
                if (x509Key.PublicKey as RSACryptoServiceProvider == null)
                    return false;
#endif
                return IsRsaAlgorithmSupported(algorithm);
            }

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

        public virtual IDecryptionProvider CreateForDecrypting(SecurityKey key, string algorithm, object additionalParam)
        {
            if (key == null)
                throw LogHelper.LogArgumentNullException(nameof(key));

            if (string.IsNullOrWhiteSpace(algorithm))
                throw LogHelper.LogArgumentNullException(nameof(algorithm));

            if (CustomCryptoProvider != null && CustomCryptoProvider.IsSupportedAlgorithm(algorithm, key))
            {
                IDecryptionProvider decryptionProvider = CustomCryptoProvider.Create(algorithm, key) as IDecryptionProvider;
                if (decryptionProvider == null)
                    throw LogHelper.LogException<InvalidOperationException>(LogMessages.IDX10646, key, algorithm, typeof(SignatureProvider));

                return decryptionProvider;
            }

            if (!IsSupportedAlgorithm(algorithm, key))
                throw LogHelper.LogException<ArgumentException>(LogMessages.IDX10634, algorithm, key);

            RsaSecurityKey rsaKey = key as RsaSecurityKey;
            if (rsaKey != null)
            {
                return null;
                //return new RsaDecryptionProvider();
            }

            X509SecurityKey x509Key = key as X509SecurityKey;
            if (x509Key != null)
            {
                return null;
                //return new RsaDecryptionProvider();
            }

            JsonWebKey jsonWebKey = key as JsonWebKey;
            if (jsonWebKey != null)
            {
                if (jsonWebKey.Kty == JsonWebAlgorithmsKeyTypes.RSA)
                    return null;
                //return new RsaDecryptionProvider();
                if (jsonWebKey.Kty == JsonWebAlgorithmsKeyTypes.EllipticCurve)
                    return null;
                // return new ECDsaDecryptProvider();
                if (jsonWebKey.Kty == JsonWebAlgorithmsKeyTypes.Octet)
                    return null;
                // return new AesKWDecryptProvider();
            }

            ECDsaSecurityKey ecdsaKey = key as ECDsaSecurityKey;
            if (ecdsaKey != null)
                return null;
            // return new ECDsaDecryptProvider();

            SymmetricSecurityKey aesKey = key as SymmetricSecurityKey;
            if (aesKey != null)
                return null;
            // return new AesKWDecryptProvider();

            return null;
        }

        public virtual IEncryptionProvider CreateForEncrypting(SecurityKey key, string algorithm, AuthenticatedEncryptionParameters authenticatedEncryptionParameters, string encodedProtectHeader)
        {
            if (algorithm == null)
                throw LogHelper.LogArgumentNullException("algorithm");

            if (algorithm.Length == 0)
                throw LogHelper.LogException<ArgumentException>("Cannot encrypt empty 'algorithm'");

            if (_keyWrapAlgorithm.Contains(algorithm))
            {
                switch (algorithm)
                {
                    case SecurityAlgorithms.RsaPKCS1:
                    case SecurityAlgorithms.RsaOAEP:
                        return new RsaProvider(key, algorithm);

                    default:
                        // TODO (Yan) : Add exception and throw
                        throw LogHelper.LogArgumentException<ArgumentException>(algorithm, "Unsupported algorithm");
                }
            }

            if (_contentEncryptAlgorithm.Contains(algorithm))
            {

                switch (algorithm)
                {
                    case SecurityAlgorithms.Aes128CbcHmacSha256:
                    case SecurityAlgorithms.Aes256CbcHmacSha512:
                        return new AesCbcHmacSha2Provider(key, algorithm, null, encodedProtectHeader);
                }
            }

            // TODO (Yan) : Add exception and throw
            throw LogHelper.LogArgumentException<ArgumentException>(algorithm, "Unsupported algorithm.");
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
        /// <para>When finished with the <see cref="SignatureProvider"/> call <see cref="ReleaseSignatureProvider(SignatureProvider)"/>.</para>
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
        /// <remarks>When finished with the <see cref="SignatureProvider"/> call <see cref="ReleaseSignatureProvider(SignatureProvider)"/>.</remarks>
        public virtual SignatureProvider CreateForVerifying(SecurityKey key, string algorithm)
        {
            return CreateProvider(key, algorithm, false);
        }

        /// <summary>
        /// When finished with a <see cref="IDecryptionProvider"/> call this method for cleanup. The default behavior is to call <see cref="IDecryptionProvider.Dispose()"/>
        /// </summary>
        /// <param name="decryptionProvider"><see cref="IDecryptionProvider"/> to be released.</param>
        public virtual void ReleaseDecryptionProvider(IDecryptionProvider decryptionProvider)
        {
            if (decryptionProvider != null)
                decryptionProvider.Dispose();
        }

        /// <summary>
        /// When finished with a <see cref="IEncryptionProvider"/> call this method for cleanup. The default behavior is to call <see cref="IEncryptionProvider.Dispose()"/>
        /// </summary>
        /// <param name="encryptionProvider"><see cref="IEncryptionProvider"/> to be released.</param>
        public virtual void ReleaseEncryptionProvider(IEncryptionProvider encryptionProvider)
        {
            if (encryptionProvider != null)
                encryptionProvider.Dispose();
        }

        /// <summary>
        /// When finished with a <see cref="SignatureProvider"/> call this method for cleanup. The default behavior is to call <see cref="SignatureProvider.Dispose()"/>
        /// </summary>
        /// <param name="signatureProvider"><see cref="SignatureProvider"/> to be released.</param>
        public virtual void ReleaseSignatureProvider(SignatureProvider signatureProvider)
        {
            if (signatureProvider != null)
                signatureProvider.Dispose();
        }

        /// <summary>
        /// When finished with a <see cref="HashAlgorithm"/> call this method for cleanup. The default behavior is to call <see cref="HashAlgorithm.Dispose()"/>
        /// </summary>
        /// <param name="hashAlgorithm"><see cref="HashAlgorithm"/> to be released.</param>
        public virtual void ReleaseHashAlgorithm(HashAlgorithm hashAlgorithm)
        {
            if (hashAlgorithm != null)
                hashAlgorithm.Dispose();
        }

        /// <summary>
        /// Returns a <see cref="HashAlgorithm"/> for a specific algorithm.
        /// </summary>
        /// <param name="algorithm">the name of the hash algorithm to create.</param>
        /// <returns>A <see cref="HashAlgorithm"/></returns>
        /// <remarks>When finished with the <see cref="HashAlgorithm"/> call <see cref="ReleaseHashAlgorithm(HashAlgorithm)"/>.</remarks>
        public virtual HashAlgorithm CreateHashAlgorithm(string algorithm)
        {
            if (CustomCryptoProvider != null && CustomCryptoProvider.IsSupportedAlgorithm(algorithm))
            {
                var hashAlgorithm = CustomCryptoProvider.Create(algorithm) as HashAlgorithm;
                if (hashAlgorithm == null)
                    throw LogHelper.LogException<InvalidOperationException>(LogMessages.IDX10647, algorithm, typeof(HashAlgorithm));

                return hashAlgorithm;
            }

            switch (algorithm)
            {
                case SecurityAlgorithms.Sha256:
                case SecurityAlgorithms.Sha256Digest:
                    return SHA256.Create();

                case SecurityAlgorithms.Sha384:
                case SecurityAlgorithms.Sha384Digest:
                    return SHA384.Create();

                case SecurityAlgorithms.Sha512:
                case SecurityAlgorithms.Sha512Digest:
                    return SHA512.Create();
            }

            throw LogHelper.LogException<InvalidOperationException>(LogMessages.IDX10640, algorithm);
        }

        private bool IsSupportedHashAlgorithm(string algorithm)
        {
            switch (algorithm)
            {
                case SecurityAlgorithms.Sha256:
                case SecurityAlgorithms.Sha256Digest:
                case SecurityAlgorithms.Sha384:
                case SecurityAlgorithms.Sha384Digest:
                case SecurityAlgorithms.Sha512:
                case SecurityAlgorithms.Sha512Digest:
                    return true;

                default:
                    return false;
            }
        }

        private SignatureProvider CreateProvider(SecurityKey key, string algorithm, bool willCreateSignatures)
        {
            if (key == null)
                throw LogHelper.LogArgumentNullException(nameof(key));

            if (string.IsNullOrWhiteSpace(algorithm))
                throw LogHelper.LogArgumentNullException(nameof(algorithm));

            if (CustomCryptoProvider != null && CustomCryptoProvider.IsSupportedAlgorithm(algorithm, key, willCreateSignatures))
            {
                SignatureProvider signatureProvider = CustomCryptoProvider.Create(algorithm, key, willCreateSignatures) as SignatureProvider;
                if (signatureProvider == null)
                    throw LogHelper.LogException<InvalidOperationException>(LogMessages.IDX10646, key, algorithm, typeof(SignatureProvider));

                return signatureProvider;
            }

            if (!IsSupportedAlgorithm(algorithm, key))
                throw LogHelper.LogException<ArgumentException>(LogMessages.IDX10634, algorithm, key);

            AsymmetricSecurityKey asymmetricKey = key as AsymmetricSecurityKey;
            if (asymmetricKey != null)
                return new AsymmetricSignatureProvider(asymmetricKey, algorithm, willCreateSignatures);

            SymmetricSecurityKey symmetricKey = key as SymmetricSecurityKey;
            if (symmetricKey != null)
                return new SymmetricSignatureProvider(symmetricKey, algorithm);

            JsonWebKey jsonWebKey = key as JsonWebKey;
            if (jsonWebKey != null)
            {
                if (jsonWebKey.Kty != null)
                {
                    if (jsonWebKey.Kty == JsonWebAlgorithmsKeyTypes.RSA || jsonWebKey.Kty == JsonWebAlgorithmsKeyTypes.EllipticCurve)
                        return new AsymmetricSignatureProvider(key, algorithm, willCreateSignatures);

                    if (jsonWebKey.Kty == JsonWebAlgorithmsKeyTypes.Octet)
                        return new SymmetricSignatureProvider(key, algorithm);
                }
            }

            throw LogHelper.LogException<ArgumentException>(LogMessages.IDX10600, typeof(SignatureProvider), typeof(SecurityKey), typeof(AsymmetricSecurityKey), typeof(SymmetricSecurityKey), key.GetType());
        }
    }
}
