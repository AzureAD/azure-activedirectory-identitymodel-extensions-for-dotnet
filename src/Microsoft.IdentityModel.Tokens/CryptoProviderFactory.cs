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
using System.ComponentModel;
using System.Security.Cryptography;
using Microsoft.IdentityModel.Logging;

namespace Microsoft.IdentityModel.Tokens
{
    /// <summary>
    /// Creates cryptographic operators by specifying a <see cref="SecurityKey"/>'s and algorithms.
    /// </summary>
    public class CryptoProviderFactory
    {
        private static CryptoProviderFactory _default;
        private static ConcurrentDictionary<string, string> _typeToAlgorithmMap = new ConcurrentDictionary<string, string>();
        private static object _cacheLock = new object();

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
        /// Gets the <see cref="CryptoProviderCache"/>
        /// </summary>
        public CryptoProviderCache CryptoProviderCache { get; } = new InMemoryCryptoProviderCache();

        /// <summary>
        /// Extensibility point for creating custom cryptographic operators.
        /// </summary>
        /// <remarks>By default, if set, <see cref="ICryptoProvider.IsSupportedAlgorithm(string, object[])"/> will be called before creating cryptographic operators.
        /// If true is returned, then <see cref="ICryptoProvider.Create(string, object[])"/> will be called. The <see cref="CryptoProviderFactory"/> will throw if the
        /// Cryptographic operator returned is not of the correct type.</remarks>
        public ICryptoProvider CustomCryptoProvider { get; set; }

        /// <summary>
        /// Gets or sets a bool controlling if <see cref="SignatureProvider"/> should be cached.
        /// </summary>
        [DefaultValue(true)]
        public bool CacheSignatureProviders { get; set; } = DefaultCacheSignatureProviders;

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

            if (SupportedAlgorithms.IsSupportedAuthenticatedEncryptionAlgorithm(algorithm, key))
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

        private KeyWrapProvider CreateKeyWrapProvider(SecurityKey key, string algorithm, bool willUnwrap)
        {
            if (key == null)
                throw LogHelper.LogArgumentNullException(nameof(key));

            if (string.IsNullOrEmpty(algorithm))
                throw LogHelper.LogArgumentNullException(nameof(algorithm));

            if (CustomCryptoProvider != null && CustomCryptoProvider.IsSupportedAlgorithm(algorithm, key, willUnwrap))
            {
                if (!(CustomCryptoProvider.Create(algorithm, key, willUnwrap) is KeyWrapProvider keyWrapProvider))
                    throw LogHelper.LogExceptionMessage(new InvalidOperationException(LogHelper.FormatInvariant(LogMessages.IDX10646, algorithm, key, typeof(SignatureProvider))));

                return keyWrapProvider;
            }

            if (key is RsaSecurityKey rsaKey && SupportedAlgorithms.IsSupportedRsaAlgorithm(algorithm, rsaKey))
                return new RsaKeyWrapProvider(key, algorithm, willUnwrap);

            if (key is X509SecurityKey x509Key && SupportedAlgorithms.IsSupportedRsaAlgorithm(algorithm, x509Key))
                return new RsaKeyWrapProvider(x509Key, algorithm, willUnwrap);

            if (key is JsonWebKey jsonWebKey)
            {
                if (jsonWebKey.Kty == JsonWebAlgorithmsKeyTypes.RSA && SupportedAlgorithms.IsSupportedRsaAlgorithm(algorithm, key))
                {
                    return new RsaKeyWrapProvider(jsonWebKey, algorithm, willUnwrap);
                }
                else if (jsonWebKey.Kty == JsonWebAlgorithmsKeyTypes.Octet && SupportedAlgorithms.IsSupportedSymmetricAlgorithm(algorithm))
                {
                    return new SymmetricKeyWrapProvider(jsonWebKey, algorithm);
                }
            }

            if (key is SymmetricSecurityKey symmetricKey && SupportedAlgorithms.IsSupportedSymmetricAlgorithm(algorithm))
                return new SymmetricKeyWrapProvider(symmetricKey, algorithm);

            throw LogHelper.LogExceptionMessage(new NotSupportedException(LogHelper.FormatInvariant(LogMessages.IDX10661, algorithm, key)));
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
            return CreateForSigning(key, algorithm, true);
        }

        /// <summary>
        /// Creates a <see cref="SignatureProvider"/> that supports the <see cref="SecurityKey"/> and algorithm.
        /// </summary>
        /// <param name="key">The <see cref="SecurityKey"/> to use for signing.</param>
        /// <param name="algorithm">The algorithm to use for signing.</param>
        /// <param name="cacheProvider">should the <see cref="SignatureProvider"/> be cached.</param>
        /// <exception cref="ArgumentNullException">'key' is null.</exception>
        /// <exception cref="ArgumentNullException">'algorithm' is null or empty.</exception>
        /// <exception cref="ArgumentOutOfRangeException"><see cref="AsymmetricSecurityKey"/>' is too small.</exception>
        /// <exception cref="ArgumentOutOfRangeException"><see cref="SymmetricSecurityKey"/> is too small.</exception>
        /// <exception cref="ArgumentException"><see cref="SecurityKey"/> is not a <see cref="AsymmetricSecurityKey"/> or a <see cref="SymmetricSecurityKey"/>.</exception>
        /// <remarks>
        /// AsymmetricSignatureProviders require access to a PrivateKey for Signing.
        /// <para>When finished with the <see cref="SignatureProvider"/> call <see cref="ReleaseSignatureProvider(SignatureProvider)"/>.</para>
        /// </remarks>
        public virtual SignatureProvider CreateForSigning(SecurityKey key, string algorithm, bool cacheProvider)
        {
            return CreateSignatureProvider(key, algorithm, true, cacheProvider);
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
            return CreateForVerifying(key, algorithm, true);
        }

        /// <summary>
        /// Returns a <see cref="SignatureProvider"/> instance supports the <see cref="SecurityKey"/> and algorithm.
        /// </summary>
        /// <param name="key">The <see cref="SecurityKey"/> to use for signing.</param>
        /// <param name="algorithm">The algorithm to use for verifying.</param>
        /// <param name="cacheProvider">should the <see cref="SignatureProvider"/> be cached.</param>
        /// <exception cref="ArgumentNullException">'key' is null.</exception>
        /// <exception cref="ArgumentNullException">'algorithm' is null or empty.</exception>
        /// <exception cref="ArgumentOutOfRangeException"><see cref="AsymmetricSecurityKey"/> is too small.</exception>
        /// <exception cref="ArgumentOutOfRangeException"><see cref="SymmetricSecurityKey"/> is too small.</exception>
        /// <exception cref="ArgumentException"><see cref="SecurityKey"/>' is not a <see cref="AsymmetricSecurityKey"/> or a <see cref="SymmetricSecurityKey"/>.</exception>
        /// <remarks>When finished with the <see cref="SignatureProvider"/> call <see cref="ReleaseSignatureProvider(SignatureProvider)"/>.</remarks>
        public virtual SignatureProvider CreateForVerifying(SecurityKey key, string algorithm, bool cacheProvider)
        {
            return CreateSignatureProvider(key, algorithm, false, cacheProvider);
        }

#if NET461 || NETSTANDARD2_0
        /// <summary>
        /// Returns a <see cref="HashAlgorithm"/> for a specific algorithm.
        /// </summary>
        /// <param name="algorithm">the name of the hash algorithm to create.</param>
        /// <returns>A <see cref="HashAlgorithm"/></returns>
        /// <remarks>When finished with the <see cref="HashAlgorithm"/> call <see cref="ReleaseHashAlgorithm(HashAlgorithm)"/>.</remarks>
        /// <exception cref="ArgumentNullException">'algorithm' is null or empty.</exception>
        /// <exception cref="InvalidOperationException">'algorithm' is not supported.</exception>
        public virtual HashAlgorithm CreateHashAlgorithm(HashAlgorithmName algorithm)
        {
            if (CustomCryptoProvider != null && CustomCryptoProvider.IsSupportedAlgorithm(algorithm.Name))
            {
                if (!(CustomCryptoProvider.Create(algorithm.Name) is HashAlgorithm hashAlgorithm))
                    throw LogHelper.LogExceptionMessage(new InvalidOperationException(LogHelper.FormatInvariant(LogMessages.IDX10647, algorithm, typeof(HashAlgorithm))));

                _typeToAlgorithmMap[hashAlgorithm.GetType().ToString()] = algorithm.Name;

                return hashAlgorithm;
            }

            if (algorithm == HashAlgorithmName.SHA256)
                    return SHA256.Create();

            if (algorithm == HashAlgorithmName.SHA384)
                return SHA384.Create();

            if (algorithm == HashAlgorithmName.SHA512)
                return SHA512.Create();

            throw LogHelper.LogExceptionMessage(new NotSupportedException(LogHelper.FormatInvariant(LogMessages.IDX10640, algorithm)));
        }
#endif

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
                if (!(CustomCryptoProvider.Create(algorithm) is HashAlgorithm hashAlgorithm))
                    throw LogHelper.LogExceptionMessage(new InvalidOperationException(LogHelper.FormatInvariant(LogMessages.IDX10647, algorithm, typeof(HashAlgorithm))));

                _typeToAlgorithmMap[hashAlgorithm.GetType().ToString()] = algorithm;

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
                if (!(CustomCryptoProvider.Create(algorithm, keyBytes) is KeyedHashAlgorithm keyedHashAlgorithm))
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

        private SignatureProvider CreateSignatureProvider(SecurityKey key, string algorithm, bool willCreateSignatures, bool cacheProvider)
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

            // types are checked in order of expected occurrence
            string typeofSignatureProvider = null;
            bool createAsymmetric = true;
            if (key is AsymmetricSecurityKey)
            {
                typeofSignatureProvider = typeof(AsymmetricSignatureProvider).ToString();
            }
            else if (key is JsonWebKey jsonWebKey)
            {
                try
                {
                    if (JsonWebKeyConverter.TryConvertToSecurityKey(jsonWebKey, out SecurityKey convertedSecurityKey))
                    {
                        if (convertedSecurityKey is AsymmetricSecurityKey)
                        {
                            typeofSignatureProvider = typeof(AsymmetricSignatureProvider).ToString();
                        }
                        else if (convertedSecurityKey is SymmetricSecurityKey)
                        {
                            typeofSignatureProvider = typeof(SymmetricSignatureProvider).ToString();
                            createAsymmetric = false;
                        }
                    }
                    // this code is simply to maintain the same exception thrown
                    else
                    {
                        if (jsonWebKey.Kty == JsonWebAlgorithmsKeyTypes.RSA || jsonWebKey.Kty == JsonWebAlgorithmsKeyTypes.EllipticCurve)
                            typeofSignatureProvider = typeof(AsymmetricSignatureProvider).ToString();
                        else if (jsonWebKey.Kty == JsonWebAlgorithmsKeyTypes.Octet)
                        {
                            typeofSignatureProvider = typeof(SymmetricSignatureProvider).ToString();
                            createAsymmetric = false;
                        }
                    }
                }
                catch(Exception ex)
                {
                    throw LogHelper.LogExceptionMessage(new InvalidOperationException(LogHelper.FormatInvariant(LogMessages.IDX10694, key, ex), ex));
                }
            }
            else if (key is SymmetricSecurityKey)
            {
                typeofSignatureProvider = typeof(SymmetricSignatureProvider).ToString();
                createAsymmetric = false;
            }

            if (typeofSignatureProvider == null)
                throw LogHelper.LogExceptionMessage(new NotSupportedException(LogHelper.FormatInvariant(LogMessages.IDX10621, typeof(SymmetricSignatureProvider), typeof(SecurityKey), typeof(AsymmetricSecurityKey), typeof(SymmetricSecurityKey), key.GetType())));

            if (!IsSupportedAlgorithm(algorithm, key))
                throw LogHelper.LogExceptionMessage(new NotSupportedException(LogHelper.FormatInvariant(LogMessages.IDX10634, algorithm, key)));

            if (CacheSignatureProviders && cacheProvider)
            {
                if (CryptoProviderCache.TryGetSignatureProvider(key, algorithm, typeofSignatureProvider, willCreateSignatures, out signatureProvider))
                    return signatureProvider;

                lock (_cacheLock)
                {
                    if (CryptoProviderCache.TryGetSignatureProvider(key, algorithm, typeofSignatureProvider, willCreateSignatures, out signatureProvider))
                        return signatureProvider;

                    if (createAsymmetric)
                        signatureProvider = new AsymmetricSignatureProvider(key, algorithm, willCreateSignatures, this);
                    else
                        signatureProvider = new SymmetricSignatureProvider(key, algorithm, willCreateSignatures);

                    CryptoProviderCache.TryAdd(signatureProvider);
                }
            }
            else if (createAsymmetric)
            {
                signatureProvider = new AsymmetricSignatureProvider(key, algorithm, willCreateSignatures);
            }
            else
            { 
                signatureProvider = new SymmetricSignatureProvider(key, algorithm, willCreateSignatures);
            }

            return signatureProvider;
        }

        /// <summary>
        /// Answers if an algorithm is supported
        /// </summary>
        /// <param name="algorithm">the name of the cryptographic algorithm</param>
        /// <returns></returns>
        public virtual bool IsSupportedAlgorithm(string algorithm)
        {
            if (CustomCryptoProvider != null && CustomCryptoProvider.IsSupportedAlgorithm(algorithm))
                return true;

            return SupportedAlgorithms.IsSupportedHashAlgorithm(algorithm);
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

            return SupportedAlgorithms.IsSupportedAlgorithm(
                        algorithm,
                        (key is JsonWebKey jsonWebKey && jsonWebKey.ConvertedSecurityKey != null)
                        ? jsonWebKey.ConvertedSecurityKey
                        : key);
        }

        /// <summary>
        /// When finished with a <see cref="HashAlgorithm"/> call this method for cleanup. The default behavior is to call <see cref="HashAlgorithm.Dispose()"/>
        /// </summary>
        /// <param name="hashAlgorithm"><see cref="HashAlgorithm"/> to be released.</param>
        public virtual void ReleaseHashAlgorithm(HashAlgorithm hashAlgorithm)
        {
            if (hashAlgorithm == null)
                throw LogHelper.LogArgumentNullException(nameof(hashAlgorithm));
            else if (CustomCryptoProvider != null && _typeToAlgorithmMap.TryGetValue(hashAlgorithm.GetType().ToString(), out var algorithm) && CustomCryptoProvider.IsSupportedAlgorithm(algorithm))
                CustomCryptoProvider.Release(hashAlgorithm);
            else 
                hashAlgorithm.Dispose();
        }

        /// <summary>
        /// When finished with a <see cref="KeyWrapProvider"/> call this method for cleanup."/>
        /// </summary>
        /// <param name="provider"><see cref="KeyWrapProvider"/> to be released.</param>
        public virtual void ReleaseKeyWrapProvider(KeyWrapProvider provider)
        {
            if (provider == null)
                throw LogHelper.LogArgumentNullException(nameof(provider));
            else if (CustomCryptoProvider != null && CustomCryptoProvider.IsSupportedAlgorithm(provider.Algorithm))
                CustomCryptoProvider.Release(provider);
            else
                provider.Dispose();
        }

        /// <summary>
        /// When finished with a <see cref="RsaKeyWrapProvider"/> call this method for cleanup."/>
        /// </summary>
        /// <param name="provider"><see cref="RsaKeyWrapProvider"/> to be released.</param>
        public virtual void ReleaseRsaKeyWrapProvider(RsaKeyWrapProvider provider)
        {
            if (provider == null)
                throw LogHelper.LogArgumentNullException(nameof(provider));
            else if (CustomCryptoProvider != null && CustomCryptoProvider.IsSupportedAlgorithm(provider.Algorithm))
                CustomCryptoProvider.Release(provider);
            else
                provider.Dispose();
        }

        /// <summary>
        /// When finished with a <see cref="SignatureProvider"/> call this method for cleanup. The default behavior is to call <see cref="SignatureProvider.Dispose()"/>
        /// </summary>
        /// <param name="signatureProvider"><see cref="SignatureProvider"/> to be released.</param>
        public virtual void ReleaseSignatureProvider(SignatureProvider signatureProvider)
        {
            if (signatureProvider == null)
                throw LogHelper.LogArgumentNullException(nameof(signatureProvider));
            else if (CustomCryptoProvider != null && CustomCryptoProvider.IsSupportedAlgorithm(signatureProvider.Algorithm))
                CustomCryptoProvider.Release(signatureProvider);
            else if (signatureProvider.CryptoProviderCache == null)
                signatureProvider.Dispose();
        }
    }
}
