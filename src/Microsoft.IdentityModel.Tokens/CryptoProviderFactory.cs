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
using System.Collections.Concurrent;
using System.Collections.Generic;
using System.ComponentModel;
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
        private static CryptoProviderFactory _default;
        private ConcurrentDictionary<string, SignatureProvider> _signingSignatureProviders = new ConcurrentDictionary<string, SignatureProvider>();
        private ConcurrentDictionary<string, SignatureProvider> _verifyingSignatureProviders = new ConcurrentDictionary<string, SignatureProvider>();

        /// <summary>
        /// Returns the default <see cref="CryptoProviderFactory"/> instance.
        /// </summary>
        public static CryptoProviderFactory Default
        {
            get { return _default; }
            set
            {
                _default = value ?? throw LogHelper.LogArgumentNullException("value");
            }
        }

        /// <summary>
        /// Gets or sets the default value for caching
        /// </summary>
        [DefaultValue(true)]
        public static bool DefaultCacheSignatureProviders { get; set; } = true;

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
        /// Gets or sets a bool controlling if <see cref="SignatureProvider"/> should be cached.
        /// </summary>
        [DefaultValue(true)]
        public bool CacheSignatureProviders { get; set; } = DefaultCacheSignatureProviders;

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

        private bool IsSupportedAuthenticatedEncryptionAlgorithm(string algorithm, SecurityKey key)
        {
            if (key == null)
                return false;

            if (string.IsNullOrEmpty(algorithm))
                return false;

            if (!(algorithm.Equals(SecurityAlgorithms.Aes128CbcHmacSha256, StringComparison.Ordinal)
               || algorithm.Equals(SecurityAlgorithms.Aes192CbcHmacSha384, StringComparison.Ordinal)
               || algorithm.Equals(SecurityAlgorithms.Aes256CbcHmacSha512, StringComparison.Ordinal)))
                return false;

            if (key is SymmetricSecurityKey)
                return true;

            if (key is JsonWebKey jsonWebKey)
                return (jsonWebKey.K != null && jsonWebKey.Kty == JsonWebAlgorithmsKeyTypes.Octet);

            return false;
        }

        private bool IsSupportedKeyWrapAlgorithm(string algorithm, SecurityKey key)
        {
            if (key == null)
                return false;

            if (string.IsNullOrEmpty(algorithm))
                return false;

            if (algorithm.Equals(SecurityAlgorithms.RsaPKCS1, StringComparison.Ordinal)
                || algorithm.Equals(SecurityAlgorithms.RsaOAEP, StringComparison.Ordinal)
                || algorithm.Equals(SecurityAlgorithms.RsaOaepKeyWrap, StringComparison.Ordinal))
            {
                if (key is RsaSecurityKey)
                    return true;

                if (key is X509SecurityKey x509Key)
                {
#if NETSTANDARD1_4
                    if (x509Key.PublicKey as RSA == null)
                        return false;
#else
                    if (x509Key.PublicKey as RSACryptoServiceProvider == null)
                        return false;
#endif
                }

                if (key is JsonWebKey jsonWebKey && jsonWebKey.Kty == JsonWebAlgorithmsKeyTypes.RSA)
                    return true;

                return false;
            }

            return false;
        }

        /// <summary>
        /// Checks if an 'algorithm, key' pair is supported.
        /// </summary>
        /// <param name="algorithm">the algorithm to check.</param>
        /// <param name="key">the <see cref="SecurityKey"/>.</param>
        /// <returns>true if 'algorithm, key' pair is supported.</returns>
        public virtual bool IsSupportedAlgorithm(string algorithm, SecurityKey key)
        {
            if (CustomCryptoProvider != null && CustomCryptoProvider.IsSupportedAlgorithm(algorithm, key))
                return true;

            if (key as RsaSecurityKey != null)
                return IsRsaAlgorithmSupported(algorithm);

            if (key is X509SecurityKey x509Key)
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

            if (key is JsonWebKey jsonWebKey)
            {
                if (jsonWebKey.Kty == JsonWebAlgorithmsKeyTypes.RSA)
                    return IsRsaAlgorithmSupported(algorithm);
                else if (jsonWebKey.Kty == JsonWebAlgorithmsKeyTypes.EllipticCurve)
                    return IsEcdsaAlgorithmSupported(algorithm);
                else if (jsonWebKey.Kty == JsonWebAlgorithmsKeyTypes.Octet)
                    return IsSymmetricAlgorithmSupported(algorithm);

                return false;
            }

            if (key is ECDsaSecurityKey ecdsaSecurityKey)
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
                case SecurityAlgorithms.EcdsaSha256Signature:
                case SecurityAlgorithms.EcdsaSha384:
                case SecurityAlgorithms.EcdsaSha384Signature:
                case SecurityAlgorithms.EcdsaSha512:
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
                case SecurityAlgorithms.RsaOAEP:
                case SecurityAlgorithms.RsaPKCS1:
                case SecurityAlgorithms.RsaOaepKeyWrap:
                    return true;
            }

            return false;
        }

        private bool IsSymmetricAlgorithmSupported(string algorithm)
        {
            switch (algorithm)
            {
                case SecurityAlgorithms.Aes128CbcHmacSha256:
                case SecurityAlgorithms.Aes192CbcHmacSha384:
                case SecurityAlgorithms.Aes256CbcHmacSha512:
                case SecurityAlgorithms.Aes128KW:
                case SecurityAlgorithms.Aes256KW:
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
        /// Creates an instance of <see cref="AuthenticatedEncryptionProvider"/> for a specific &lt;SecurityKey, Algorithm>.
        /// </summary>
        /// <param name="key">the <see cref="SecurityKey"/> to use.</param>
        /// <param name="algorithm">the algorithm to use.</param>
        /// <returns>an instance of <see cref="AuthenticatedEncryptionProvider"/></returns>
        /// <exception cref="ArgumentNullException">'key' is null.</exception>
        /// <exception cref="ArgumentNullException">'algorithm' is null or empty.</exception>
        /// <exception cref="ArgumentException">'key' is not a <see cref="SymmetricSecurityKey"/>.</exception>
        /// <exception cref="ArgumentException">'algorithm, key' pair is not supported.</exception>
        public virtual AuthenticatedEncryptionProvider CreateAuthenticatedEncryptionProvider(SecurityKey key, string algorithm)
        {
            if (key == null)
                throw LogHelper.LogArgumentNullException(nameof(key));

            if (string.IsNullOrEmpty(algorithm))
                throw LogHelper.LogArgumentNullException(nameof(algorithm));

            if (CustomCryptoProvider != null && CustomCryptoProvider.IsSupportedAlgorithm(algorithm, key))
            {
                var cryptoProvider = CustomCryptoProvider.Create(algorithm, key) as AuthenticatedEncryptionProvider;
                if (cryptoProvider == null)
                    throw LogHelper.LogExceptionMessage(new InvalidOperationException(LogHelper.FormatInvariant(LogMessages.IDX10646, algorithm, key, typeof(AuthenticatedEncryptionProvider))));

                return cryptoProvider;
            }

            if (IsSupportedAuthenticatedEncryptionAlgorithm(algorithm, key))
                return new AuthenticatedEncryptionProvider(key, algorithm);

            throw LogHelper.LogExceptionMessage(new ArgumentException(LogHelper.FormatInvariant(LogMessages.IDX10652, algorithm), nameof(algorithm)));
        }

        /// <summary>
        /// Creates an instance of <see cref="KeyWrapProvider"/> for a specific &lt;SecurityKey, Algorithm>.
        /// </summary>
        /// <param name="key">the <see cref="SecurityKey"/> to use.</param>
        /// <param name="algorithm">the algorithm to use.</param>
        /// <returns>an instance of <see cref="KeyWrapProvider"/></returns>
        /// <exception cref="ArgumentNullException">'key' is null.</exception>
        /// <exception cref="ArgumentNullException">'algorithm' is null or empty.</exception>
        /// <exception cref="ArgumentException">If <see cref="SecurityKey"/> and algorithm pair are not supported.</exception>
        /// <remarks>
        /// <para>When finished with the <see cref="KeyWrapProvider"/> call <see cref="ReleaseKeyWrapProvider(KeyWrapProvider)"/>.</para>
        /// </remarks>
        public virtual KeyWrapProvider CreateKeyWrapProvider(SecurityKey key, string algorithm)
        {
            return CreateKeyWrapProvider(key, algorithm, false);
        }

        /// <summary>
        /// Creates an instance of <see cref="KeyWrapProvider"/> for a specific &lt;SecurityKey, Algorithm>.
        /// </summary>
        /// <param name="key">the <see cref="SecurityKey"/> to use.</param>
        /// <param name="algorithm">the algorithm to use.</param>
        /// <returns>an instance of <see cref="KeyWrapProvider"/></returns>
        /// <exception cref="ArgumentNullException">'key' is null.</exception>
        /// <exception cref="ArgumentNullException">'algorithm' is null or empty.</exception>
        /// <exception cref="ArgumentException">If <see cref="SecurityKey"/> and algorithm pair are not supported.</exception>
        /// <remarks>
        /// <para>When finished with the <see cref="KeyWrapProvider"/> call <see cref="ReleaseKeyWrapProvider(KeyWrapProvider)"/>.</para>
        /// </remarks>
        public virtual KeyWrapProvider CreateKeyWrapProviderForUnwrap(SecurityKey key, string algorithm)
        {
            return CreateKeyWrapProvider(key, algorithm, true);
        }

        private KeyWrapProvider CreateKeyWrapProvider(SecurityKey key, string algorithm, bool willUnwrap)
        {
            if (key == null)
                throw LogHelper.LogArgumentNullException(nameof(key));

            if (string.IsNullOrEmpty(algorithm))
                throw LogHelper.LogArgumentNullException(nameof(algorithm));

            if (CustomCryptoProvider != null && CustomCryptoProvider.IsSupportedAlgorithm(algorithm, key, willUnwrap))
            {
                KeyWrapProvider keyWrapProvider = CustomCryptoProvider.Create(algorithm, key, willUnwrap) as KeyWrapProvider;
                if (keyWrapProvider == null)
                    throw LogHelper.LogExceptionMessage(new InvalidOperationException(LogHelper.FormatInvariant(LogMessages.IDX10646, algorithm, key, typeof(SignatureProvider))));

                return keyWrapProvider;
            }

            if (key is RsaSecurityKey rsaKey && IsRsaAlgorithmSupported(algorithm))
                return new RsaKeyWrapProvider(key, algorithm, willUnwrap);

            if (key is X509SecurityKey x509Key && IsRsaAlgorithmSupported(algorithm))
                return new RsaKeyWrapProvider(x509Key, algorithm, willUnwrap);

            if (key is JsonWebKey jsonWebKey)
            {
                if (jsonWebKey.Kty == JsonWebAlgorithmsKeyTypes.RSA && IsRsaAlgorithmSupported(algorithm))
                {
                    return new RsaKeyWrapProvider(jsonWebKey, algorithm, willUnwrap);
                }
                else if (jsonWebKey.Kty == JsonWebAlgorithmsKeyTypes.Octet && IsSymmetricAlgorithmSupported(algorithm))
                {
                    return new SymmetricKeyWrapProvider(jsonWebKey, algorithm);
                }
            }

            if (key is SymmetricSecurityKey symmetricKey && IsSymmetricAlgorithmSupported(algorithm))
                return new SymmetricKeyWrapProvider(symmetricKey, algorithm);

            throw LogHelper.LogExceptionMessage(new NotSupportedException(LogHelper.FormatInvariant(LogMessages.IDX10661, algorithm, key)));
        }

        /// <summary>
        /// Creates a <see cref="SignatureProvider"/> that supports the <see cref="SecurityKey"/> and algorithm.
        /// </summary>
        /// <param name="key">The <see cref="SecurityKey"/> to use for signing.</param>
        /// <param name="algorithm">The algorithm to use for signing.</param>
        /// <exception cref="ArgumentNullException">'key' is null.</exception>
        /// <exception cref="ArgumentNullException">'algorithm' is null or empty.</exception>
        /// <exception cref="ArgumentOutOfRangeException"><see cref="AsymmetricSecurityKey"/>' is too small.</exception>
        /// <exception cref="ArgumentOutOfRangeException"><see cref="SymmetricSecurityKey"/> is too small.</exception>
        /// <exception cref="ArgumentException"><see cref="SecurityKey"/> is not a <see cref="AsymmetricSecurityKey"/> or a <see cref="SymmetricSecurityKey"/>.</exception>
        /// <remarks>
        /// AsymmetricSignatureProviders require access to a PrivateKey for Signing.
        /// <para>When finished with the <see cref="SignatureProvider"/> call <see cref="ReleaseSignatureProvider(SignatureProvider)"/>.</para>
        /// </remarks>
        public virtual SignatureProvider CreateForSigning(SecurityKey key, string algorithm)
        {
            return CreateSignatureProvider(key, algorithm, true);
        }

        /// <summary>
        /// Returns the cache key to use when looking up an entry into the cache for a <see cref="SignatureProvider" />
        /// </summary>
        /// <param name="key"></param>
        /// <param name="algorithm"></param>
        /// <returns>the cache key to use for lookup</returns>
        public virtual string GetSignatureProviderCacheKey(SecurityKey key, string algorithm)
        {
            return $"{key.GetType()}-{key.KeyId}-{algorithm}";
        }

        /// <summary>
        /// Returns a <see cref="SignatureProvider"/> instance supports the <see cref="SecurityKey"/> and algorithm.
        /// </summary>
        /// <param name="key">The <see cref="SecurityKey"/> to use for signing.</param>
        /// <param name="algorithm">The algorithm to use for verifying.</param>
        /// <exception cref="ArgumentNullException">'key' is null.</exception>
        /// <exception cref="ArgumentNullException">'algorithm' is null or empty.</exception>
        /// <exception cref="ArgumentOutOfRangeException"><see cref="AsymmetricSecurityKey"/> is too small.</exception>
        /// <exception cref="ArgumentOutOfRangeException"><see cref="SymmetricSecurityKey"/> is too small.</exception>
        /// <exception cref="ArgumentException"><see cref="SecurityKey"/>' is not a <see cref="AsymmetricSecurityKey"/> or a <see cref="SymmetricSecurityKey"/>.</exception>
        /// <remarks>When finished with the <see cref="SignatureProvider"/> call <see cref="ReleaseSignatureProvider(SignatureProvider)"/>.</remarks>
        public virtual SignatureProvider CreateForVerifying(SecurityKey key, string algorithm)
        {
            return CreateSignatureProvider(key, algorithm, false);
        }

        /// <summary>
        /// When finished with a <see cref="SignatureProvider"/> call this method for cleanup. The default behavior is to call <see cref="SignatureProvider.Dispose()"/>
        /// </summary>
        /// <param name="signatureProvider"><see cref="SignatureProvider"/> to be released.</param>
        public virtual void ReleaseSignatureProvider(SignatureProvider signatureProvider)
        {
            if (signatureProvider != null && !CacheSignatureProviders)
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
        /// When finished with a <see cref="KeyWrapProvider"/> call this method for cleanup."/>
        /// </summary>
        /// <param name="provider"><see cref="KeyWrapProvider"/> to be released.</param>
        public virtual void ReleaseKeyWrapProvider(KeyWrapProvider provider)
        {
            if (provider != null)
                provider.Dispose();
        }

        /// <summary>
        /// When finished with a <see cref="RsaKeyWrapProvider"/> call this method for cleanup."/>
        /// </summary>
        /// <param name="provider"><see cref="RsaKeyWrapProvider"/> to be released.</param>
        public virtual void ReleaseRsaKeyWrapProvider(RsaKeyWrapProvider provider)
        {
            if (provider != null)
                provider.Dispose();
        }

        /// <summary>
        /// Returns a <see cref="HashAlgorithm"/> for a specific algorithm.
        /// </summary>
        /// <param name="algorithm">the name of the hash algorithm to create.</param>
        /// <returns>A <see cref="HashAlgorithm"/></returns>
        /// <remarks>When finished with the <see cref="HashAlgorithm"/> call <see cref="ReleaseHashAlgorithm(HashAlgorithm)"/>.</remarks>
        /// <exception cref="ArgumentNullException">'algorithm' is null or empty.</exception>
        /// <exception cref="InvalidOperationException">'algorithm' is not supported.</exception>
        public virtual HashAlgorithm CreateHashAlgorithm(string algorithm)
        {
            if (string.IsNullOrEmpty(algorithm))
                throw LogHelper.LogArgumentNullException(nameof(algorithm));

            if (CustomCryptoProvider != null && CustomCryptoProvider.IsSupportedAlgorithm(algorithm))
            {
                var hashAlgorithm = CustomCryptoProvider.Create(algorithm) as HashAlgorithm;
                if (hashAlgorithm == null)
                    throw LogHelper.LogExceptionMessage(new InvalidOperationException(LogHelper.FormatInvariant(LogMessages.IDX10647, algorithm, typeof(HashAlgorithm))));

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

            throw LogHelper.LogExceptionMessage(new NotSupportedException(LogHelper.FormatInvariant(LogMessages.IDX10640, algorithm)));
        }

        /// <summary>
        /// Returns a <see cref="KeyedHashAlgorithm"/> for a specific algorithm.
        /// </summary>
        /// <param name="algorithm">the keyed hash algorithm to create.</param>
        /// <param name="keyBytes">bytes to use to create the Keyed Hash</param>
        /// <returns>A <see cref="HashAlgorithm"/></returns>
        /// <remarks>When finished with the <see cref="HashAlgorithm"/> call <see cref="ReleaseHashAlgorithm(HashAlgorithm)"/>.</remarks>
        /// <exception cref="ArgumentNullException">'algorithm' is null or empty.</exception>
        /// <exception cref="InvalidOperationException">'algorithm' is not supported.</exception>
        public virtual KeyedHashAlgorithm CreateKeyedHashAlgorithm(byte[] keyBytes, string algorithm)
        {
            if (keyBytes == null)
                throw LogHelper.LogArgumentNullException(nameof(keyBytes));

            if (string.IsNullOrEmpty(algorithm))
                throw LogHelper.LogArgumentNullException(nameof(algorithm));

            if (CustomCryptoProvider != null && CustomCryptoProvider.IsSupportedAlgorithm(algorithm, keyBytes))
            {
                var keyedHashAlgorithm = CustomCryptoProvider.Create(algorithm, keyBytes) as KeyedHashAlgorithm;
                if (keyedHashAlgorithm == null)
                    throw LogHelper.LogExceptionMessage(new InvalidOperationException(LogHelper.FormatInvariant(LogMessages.IDX10647, algorithm, typeof(KeyedHashAlgorithm))));

                return keyedHashAlgorithm;
            }

            switch (algorithm)
            {
                case SecurityAlgorithms.HmacSha256Signature:
                case SecurityAlgorithms.HmacSha256:
                    return new HMACSHA256(keyBytes);

                case SecurityAlgorithms.HmacSha384Signature:
                case SecurityAlgorithms.HmacSha384:
                    return new HMACSHA384(keyBytes);

                case SecurityAlgorithms.HmacSha512Signature:
                case SecurityAlgorithms.HmacSha512:
                    return new HMACSHA512(keyBytes);

                default:
                    throw LogHelper.LogExceptionMessage(new NotSupportedException(LogHelper.FormatInvariant(LogMessages.IDX10666, algorithm)));
            }
        }

        private SignatureProvider CreateSignatureProvider(SecurityKey key, string algorithm, bool willCreateSignatures)
        {
            if (key == null)
                throw LogHelper.LogArgumentNullException(nameof(key));

            if (string.IsNullOrEmpty(algorithm))
                throw LogHelper.LogArgumentNullException(nameof(algorithm));

            SignatureProvider signatureProvider = null;
            if (CustomCryptoProvider != null && CustomCryptoProvider.IsSupportedAlgorithm(algorithm, key, willCreateSignatures))
            {
                signatureProvider = CustomCryptoProvider.Create(algorithm, key, willCreateSignatures) as SignatureProvider;
                if (signatureProvider == null)
                    throw LogHelper.LogExceptionMessage(new InvalidOperationException(LogHelper.FormatInvariant(LogMessages.IDX10646, algorithm, key, typeof(SignatureProvider))));

                return signatureProvider;
            }

            signatureProvider = GetCachedSignatureProvider(GetSignatureProviderCacheKey(key, algorithm), willCreateSignatures);
            if (signatureProvider != null)
                return signatureProvider;

            if (!IsSupportedAlgorithm(algorithm, key))
                throw LogHelper.LogExceptionMessage(new NotSupportedException(LogHelper.FormatInvariant(LogMessages.IDX10634, algorithm, key)));

            if (key is AsymmetricSecurityKey asymmetricKey)
                signatureProvider = new AsymmetricSignatureProvider(asymmetricKey, algorithm, willCreateSignatures);

            else if (key is SymmetricSecurityKey symmetricKey)
                signatureProvider = new SymmetricSignatureProvider(symmetricKey, algorithm);

            else if (key is JsonWebKey jsonWebKey)
            {
                if (jsonWebKey.Kty != null)
                {
                    if (jsonWebKey.Kty == JsonWebAlgorithmsKeyTypes.RSA || jsonWebKey.Kty == JsonWebAlgorithmsKeyTypes.EllipticCurve)
                        signatureProvider =  new AsymmetricSignatureProvider(key, algorithm, willCreateSignatures);

                    if (jsonWebKey.Kty == JsonWebAlgorithmsKeyTypes.Octet)
                        signatureProvider = new SymmetricSignatureProvider(key, algorithm);
                }
            }

            if (signatureProvider == null)
                throw LogHelper.LogExceptionMessage(new NotSupportedException(LogHelper.FormatInvariant(LogMessages.IDX10800, typeof(SignatureProvider), typeof(SecurityKey), typeof(AsymmetricSecurityKey), typeof(SymmetricSecurityKey), key.GetType())));

            if (CacheSignatureProviders)
                CacheSignatureProvider(signatureProvider, willCreateSignatures);

            return signatureProvider;
        }

        /// <summary>
        /// Returns a <see cref="SignatureProvider"/> from the cache
        /// </summary>
        /// <param name="cacheKey">the key to find the <see cref="SignatureProvider"/></param>
        /// <param name="willCreateSignatures">allows partitioning between public and private <see cref="SignatureProvider"/>.</param>
        public virtual SignatureProvider GetCachedSignatureProvider(string cacheKey, bool willCreateSignatures)
        {
            if (willCreateSignatures)
            {
                if (_signingSignatureProviders.TryGetValue(cacheKey, out SignatureProvider signatureProvider))
                    return signatureProvider;
            }
            else
            {
                if (_verifyingSignatureProviders.TryGetValue(cacheKey, out SignatureProvider signatureProvider))
                    return signatureProvider;
            }

            return null;
        }

        /// <summary>
        /// Removes a <see cref="SignatureProvider"/> from the cache
        /// </summary>
        /// <param name="signatureProvider"><see cref="SignatureProvider"/> to cache</param>
        public virtual void RemoveCachedSignatureProvider(SignatureProvider signatureProvider)
        {
            if (signatureProvider == null)
                throw LogHelper.LogArgumentNullException(nameof(signatureProvider));

            if (string.IsNullOrEmpty(signatureProvider.Key.KeyId))
                return;

            var cacheKey = GetSignatureProviderCacheKey(signatureProvider.Key, signatureProvider.Algorithm);
            if (signatureProvider.WillCreateSignatures)
                _signingSignatureProviders.TryRemove(cacheKey, out SignatureProvider provider);
            else
                _verifyingSignatureProviders.TryRemove(cacheKey, out SignatureProvider provider);
        }

        /// <summary>
        /// Adds a <see cref="SignatureProvider"/> to the cache
        /// </summary>
        /// <param name="signatureProvider"><see cref="SignatureProvider"/> to cache</param>
        /// <param name="willCreateSignatures">allows partitioning between public and private <see cref="SignatureProvider"/>.</param>
        public virtual void CacheSignatureProvider(SignatureProvider signatureProvider, bool willCreateSignatures)
        {
            if (signatureProvider == null)
                throw LogHelper.LogArgumentNullException(nameof(signatureProvider));

            if (string.IsNullOrEmpty(signatureProvider.Key.KeyId))
                return;

            var cacheKey = GetSignatureProviderCacheKey(signatureProvider.Key, signatureProvider.Algorithm);
            if (willCreateSignatures)
                _signingSignatureProviders.TryAdd(cacheKey, signatureProvider);
            else
                _verifyingSignatureProviders.TryAdd(cacheKey, signatureProvider);
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
    }
}
