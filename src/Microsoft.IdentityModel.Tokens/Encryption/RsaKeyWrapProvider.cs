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
using System.Globalization;
using Microsoft.IdentityModel.Logging;

namespace Microsoft.IdentityModel.Tokens
{
    /// <summary>
    /// Provides RSA Wrap key and Unwrap key services.
    /// </summary>
    public class RsaKeyWrapProvider : IDisposable
    {
#if NETSTANDARD1_4
        private RSA _rsa;
#else
        private RSACryptoServiceProvider _rsaCryptoServiceProvider;
#endif
        private RSACryptoServiceProviderProxy _rsaCryptoServiceProviderProxy;
        private bool _disposed = false;

        /// <summary>
        /// Initializes a new instance of the <see cref="RsaKeyWrapProvider"/> class used for wrap key and unwrap key.
        /// <param name="key">The <see cref="SecurityKey"/> that will be used for crypto operations.</param>
        /// <param name="algorithm">The KeyWrap algorithm to apply.</param>
        /// <param name="willDecrypt">Whether this <see cref="RsaKeyWrapProvider"/> is required to create decrypts then set this to true.</param>
        /// <exception cref="ArgumentNullException">'key' is null.</exception>
        /// <exception cref="ArgumentNullException">'algorithm' is null.</exception>
        /// <exception cref="ArgumentOutOfRangeException">The keysize doesn't match the algorithm.</exception>
        /// <exception cref="ArgumentOutOfRangeException">The <see cref="SecurityKey"/>  is not supported.</exception>
        /// <exception cref="ArgumentException">If <see cref="SecurityKey"/> and algorithm pair are not supported.</exception>
        /// <exception cref="InvalidOperationException">Failed to create RSA algorithm with provided key and algorithm.</exception>
        public RsaKeyWrapProvider(SecurityKey key, string algorithm, bool willDecrypt)
        {
            if (key == null)
                throw LogHelper.LogArgumentNullException(nameof(key));

            if (string.IsNullOrEmpty(algorithm))
                throw LogHelper.LogArgumentNullException(nameof(algorithm));

            if (key.KeySize < 2048)
            {
                string keyId = key.KeyId ?? string.Empty;
                throw LogHelper.LogExceptionMessage(new ArgumentOutOfRangeException("key.KeySize", string.Format(CultureInfo.InvariantCulture, LogMessages.IDX10662, algorithm, 2048, keyId, key.KeySize)));
            }

            if (!IsSupportedAlgorithm(key, algorithm, willDecrypt))
                throw LogHelper.LogExceptionMessage(new ArgumentException(string.Format(CultureInfo.InvariantCulture, LogMessages.IDX10671, algorithm, key)));

            Algorithm = algorithm;
            Key = key;

            ResolveRsaAlgorithm(key, algorithm, willDecrypt);
#if NETSTANDARD1_4
            if (_rsa == null && _rsaCryptoServiceProviderProxy == null)
                throw LogHelper.LogExceptionMessage(new InvalidOperationException(string.Format(CultureInfo.InvariantCulture, LogMessages.IDX10672)));
#else
            if (_rsaCryptoServiceProvider == null && _rsaCryptoServiceProviderProxy == null)
                throw LogHelper.LogExceptionMessage(new InvalidOperationException(string.Format(CultureInfo.InvariantCulture, LogMessages.IDX10672)));
#endif
        }

        /// <summary>
        /// Gets the KeyWrap algorithm that is being used.
        /// </summary>
        public string Algorithm { get; private set; }

        /// <summary>
        /// Gets or sets a user context for a <see cref="KeyWrapProvider"/>.
        /// </summary>
        /// <remarks>This is null by default. This can be used by runtimes or for extensibility scenarios.</remarks>
        public string Context { get; set; }

        /// <summary>
        /// Gets the <see cref="SecurityKey"/> that is being used.
        /// </summary>
        public SecurityKey Key { get; private set; }

        private RSAParameters CreateRsaParametersFromJsonWebKey(JsonWebKey webKey, bool isPrivate)
        {
            if (webKey == null)
                throw LogHelper.LogArgumentNullException(nameof(webKey));

            if (webKey.N == null || webKey.E == null)
                throw LogHelper.LogExceptionMessage(new ArgumentException(String.Format(CultureInfo.InvariantCulture, LogMessages.IDX10700, webKey)));

            RSAParameters parameters;
            if (isPrivate)
            {
                if (webKey.D == null || webKey.DP == null || webKey.DQ == null || webKey.QI == null || webKey.P == null || webKey.Q == null)
                    throw LogHelper.LogExceptionMessage(new ArgumentNullException(nameof(webKey), String.Format(CultureInfo.InvariantCulture, LogMessages.IDX10702, webKey)));

                parameters = new RSAParameters()
                {
                    D = Base64UrlEncoder.DecodeBytes(webKey.D),
                    DP = Base64UrlEncoder.DecodeBytes(webKey.DP),
                    DQ = Base64UrlEncoder.DecodeBytes(webKey.DQ),
                    Exponent = Base64UrlEncoder.DecodeBytes(webKey.E),
                    Modulus = Base64UrlEncoder.DecodeBytes(webKey.N),
                    InverseQ = Base64UrlEncoder.DecodeBytes(webKey.QI),
                    P = Base64UrlEncoder.DecodeBytes(webKey.P),
                    Q = Base64UrlEncoder.DecodeBytes(webKey.Q)
                };
            }
            else
            {
                parameters = new RSAParameters()
                {
                    Exponent = Base64UrlEncoder.DecodeBytes(webKey.E),
                    Modulus = Base64UrlEncoder.DecodeBytes(webKey.N),
                };
            }
            return parameters;
        }

        /// <summary>
        /// Calls <see cref="Dispose(bool)"/> and <see cref="GC.SuppressFinalize"/>
        /// </summary>
        public void Dispose()
        {
            this.Dispose(true);
            GC.SuppressFinalize(this);
        }

        /// <summary>
        /// Disposes of internal components.
        /// </summary>
        /// <param name="disposing">true, if called from Dispose(), false, if invoked inside a finalizer.</param>
        protected virtual void Dispose(bool disposing)
        {
            if (!_disposed)
            {
                if (disposing)
                {
#if NETSTANDARD1_4
                    if (_rsa != null)
                    {
                        _rsa.Dispose();
                        _rsa = null;
                    }
#else
                    if (_rsaCryptoServiceProvider != null)
                    {
                        _rsaCryptoServiceProvider.Dispose();
                        _rsaCryptoServiceProvider = null;
                    }
#endif

                    if (_rsaCryptoServiceProviderProxy != null)
                        _rsaCryptoServiceProviderProxy.Dispose();

                    _disposed = true;
                }
            }
        }

        /// <summary>
        /// Checks if an algorithm is supported.
        /// </summary>
        /// <param name="key">The <see cref="SecurityKey"/> that will be used for crypto operations.</param>
        /// <param name="algorithm">The KeyWrap algorithm to apply.</param>
        /// <param name = "willDecrypt"> Whether this <see cref = "RsaKeyWrapProvider" /> is required to create decrypts then set this to true.</param>
        /// <returns>true if the algorithm is supported; otherwise, false.</returns>
        protected virtual bool IsSupportedAlgorithm(SecurityKey key, string algorithm, bool willDecrypt)
        {
            if (key == null)
                return false;

            if (string.IsNullOrEmpty(algorithm))
                return false;

            if (algorithm.Equals(SecurityAlgorithms.RsaPKCS1, StringComparison.Ordinal)
                || algorithm.Equals(SecurityAlgorithms.RsaOAEP, StringComparison.Ordinal)
                || algorithm.Equals(SecurityAlgorithms.RsaOAEP256, StringComparison.Ordinal))
            {
                if (key as RsaSecurityKey != null)
                    return true;

                X509SecurityKey x509Key = key as X509SecurityKey;
                if (x509Key != null)
                {
#if NETSTANDARD1_4
                    if (willDecrypt)
                    {
                        if (x509Key.PrivateKey as RSACryptoServiceProvider != null || x509Key.PrivateKey as RSA != null)
                            return true;
                    }
                    else
                    {
                        if (x509Key.PublicKey as RSA != null)
                            return true;
                    }
#else
                    if (willDecrypt)
                    {
                        if (x509Key.PrivateKey as RSACryptoServiceProvider != null)
                            return true;
                    }
                    else
                    {
                        if (x509Key.PublicKey as RSACryptoServiceProvider != null)
                            return true;
                    }
#endif

                    return false;
                }

                var jsonWebKey = key as JsonWebKey;
                if (jsonWebKey.Kty == JsonWebAlgorithmsKeyTypes.RSA)
                    return true;
            }

            return false;
        }

#if NETSTANDARD1_4
        /// <summary>
        /// Initialize RSA algorithm.
        /// </summary>
        /// <param name="key">The <see cref="SecurityKey"/> that will be used for crypto operations.</param>
        /// <param name="algorithm">The RSA KeyWrap algorithm to apply.</param>
        /// <param name="willDecrypt">Whether this <see cref="RsaKeyWrapProvider"/> is required to create decrypts then set this to true.</param>
        /// <exception cref="ArgumentOutOfRangeException">The <see cref="SecurityKey"/> is not supported.</exception>
        protected virtual void ResolveRsaAlgorithm(SecurityKey key, string algorithm, bool willDecrypt)
        {
            RsaSecurityKey rsaKey = key as RsaSecurityKey;
            if (rsaKey != null)
            {
                if (rsaKey.Rsa != null)
                {
                    _rsa = rsaKey.Rsa;
                    return;
                }

                _rsa = RSA.Create();
                if (_rsa != null)
                {
                    _rsa.ImportParameters(rsaKey.Parameters);
                    return;
                }
            }

            X509SecurityKey x509Key = key as X509SecurityKey;
            if (x509Key != null)
            {
                if (willDecrypt)
                {
                    RSACryptoServiceProvider rsaCsp = x509Key.PrivateKey as RSACryptoServiceProvider;
                    if (rsaCsp != null)
                        _rsaCryptoServiceProviderProxy = new RSACryptoServiceProviderProxy(rsaCsp);
                    else
                        _rsa = x509Key.PrivateKey as RSA;
                }
                else
                    _rsa = x509Key.PublicKey as RSA;

                return;
            }

            JsonWebKey webKey = key as JsonWebKey;
            if (webKey.Kty == JsonWebAlgorithmsKeyTypes.RSA)
            {
                RSAParameters parameters = CreateRsaParametersFromJsonWebKey(webKey, willDecrypt);

                _rsa = RSA.Create();
                if (_rsa != null)
                {
                    _rsa.ImportParameters(parameters);
                    return;
                }
            }

            throw LogHelper.LogExceptionMessage(new ArgumentOutOfRangeException(nameof(key), String.Format(CultureInfo.InvariantCulture, LogMessages.IDX10641, key)));
        }
#else
        /// <summary>
        /// Initialize RSA algorithm.
        /// </summary>
        /// <param name="key">The <see cref="SecurityKey"/> that will be used for crypto operations.</param>
        /// <param name="algorithm">The RSA KeyWrap algorithm to apply.</param>
        /// <param name="willDecrypt">Whether this <see cref="RsaKeyWrapProvider"/> is required to create decrypts then set this to true.</param>
        /// <exception cref="ArgumentOutOfRangeException">The <see cref="SecurityKey"/> is not supported.</exception>
        protected virtual void ResolveRsaAlgorithm(SecurityKey key, string algorithm, bool willDecrypt)
        {
            RsaSecurityKey rsaKey = key as RsaSecurityKey;
            if (rsaKey != null)
            {
                if (rsaKey.Rsa != null)
                    _rsaCryptoServiceProvider = rsaKey.Rsa as RSACryptoServiceProvider;

                if (_rsaCryptoServiceProvider == null)
                {
                    _rsaCryptoServiceProvider = new RSACryptoServiceProvider();
                    (_rsaCryptoServiceProvider as RSA).ImportParameters(rsaKey.Parameters);
                }

                return;
            }

            X509SecurityKey x509Key = key as X509SecurityKey;
            if (x509Key != null)
            {
                if (willDecrypt)
                    _rsaCryptoServiceProviderProxy = new RSACryptoServiceProviderProxy(x509Key.PrivateKey as RSACryptoServiceProvider);
                else
                    _rsaCryptoServiceProviderProxy = new RSACryptoServiceProviderProxy(x509Key.PublicKey as RSACryptoServiceProvider);

                return;
            }

            JsonWebKey webKey = key as JsonWebKey;
            if (webKey.Kty == JsonWebAlgorithmsKeyTypes.RSA)
            {
                RSAParameters parameters = CreateRsaParametersFromJsonWebKey(webKey, willDecrypt);
                _rsaCryptoServiceProvider = new RSACryptoServiceProvider();
                (_rsaCryptoServiceProvider as RSA).ImportParameters(parameters);

                return;
            }

            throw LogHelper.LogExceptionMessage(new ArgumentOutOfRangeException(nameof(key), String.Format(CultureInfo.InvariantCulture, LogMessages.IDX10641, key)));
        }
#endif

        /// <summary>
        /// Unwrap the wrappedKey
        /// </summary>
        /// <param name="wrappedKey">the wrapped key to unwrap</param>
        /// <returns>Unwrap wrapped key</returns>
        /// <exception cref="ArgumentNullException">'wrappedKey' is null or empty.</exception>
        /// <exception cref="ObjectDisposedException">If <see cref="RsaKeyWrapProvider.Dispose(bool)"/> has been called.</exception>
        /// <exception cref="SecurityTokenKeyWrapException">Failed to unwrap the wrappedKey.</exception>
        /// <exception cref="InvalidOperationException">If the internal RSA algorithm is null.</exception>
        public virtual byte[] UnwrapKey(byte[] wrappedKey)
        {
            if (wrappedKey == null || wrappedKey.Length == 0)
                throw LogHelper.LogArgumentNullException("wrappedKey");

            if (_disposed)
                throw LogHelper.LogExceptionMessage(new ObjectDisposedException(GetType().ToString()));

            bool fOAEP = false;

#if NETSTANDARD1_4
            RSAEncryptionPadding padding = RSAEncryptionPadding.Pkcs1;
            if (Algorithm.Equals(SecurityAlgorithms.RsaOAEP, StringComparison.Ordinal))
            {
                padding = RSAEncryptionPadding.OaepSHA1;
            }
            else if (Algorithm.Equals(SecurityAlgorithms.RsaOAEP256, StringComparison.Ordinal))
            {
                padding = RSAEncryptionPadding.OaepSHA256;
            }

            try
            {
                if (_rsa != null)
                    return _rsa.Decrypt(wrappedKey, padding);
                else if (_rsaCryptoServiceProviderProxy != null)
                    return _rsaCryptoServiceProviderProxy.Decrypt(wrappedKey, fOAEP);
            }
            catch (Exception ex)
            {
                throw LogHelper.LogExceptionMessage(new SecurityTokenKeyWrapException(string.Format(CultureInfo.InvariantCulture, LogMessages.IDX10659, ex)));
            }
#else
            if (Algorithm.Equals(SecurityAlgorithms.RsaOAEP, StringComparison.Ordinal))
            {
                fOAEP = true;
            }

            try
            {
                if (_rsaCryptoServiceProvider != null)
                    return _rsaCryptoServiceProvider.Decrypt(wrappedKey, fOAEP);
                else if (_rsaCryptoServiceProviderProxy != null)
                    return _rsaCryptoServiceProviderProxy.Decrypt(wrappedKey, fOAEP);
            }
            catch (Exception ex)
            {
                throw LogHelper.LogExceptionMessage(new SecurityTokenKeyWrapException(string.Format(CultureInfo.InvariantCulture, LogMessages.IDX10659, ex)));
            }
#endif

            throw LogHelper.LogExceptionMessage(new InvalidOperationException(LogMessages.IDX10644));
        }

        /// <summary>
        /// Wrap the 'keyToWrap'
        /// </summary>
        /// <param name="keyToWrap">the key to be wrapped</param>
        /// <returns>The wrapped key</returns>
        /// <exception cref="ArgumentNullException">'keyToWrap' is null or empty.</exception>
        /// <exception cref="ObjectDisposedException">If <see cref="RsaKeyWrapProvider.Dispose(bool)"/> has been called.</exception>
        /// <exception cref="SecurityTokenKeyWrapException">Failed to wrap the keyToWrap.</exception>
        /// <exception cref="InvalidOperationException">If the internal RSA algorithm is null.</exception>
        public virtual byte[] WrapKey(byte[] keyToWrap)
        {
            if (keyToWrap == null || keyToWrap.Length == 0)
                throw LogHelper.LogArgumentNullException("keyToWrap");

            if (_disposed)
                throw LogHelper.LogExceptionMessage(new ObjectDisposedException(GetType().ToString()));

            bool fOAEP = false;
            if (Algorithm.Equals(SecurityAlgorithms.RsaOAEP, StringComparison.Ordinal))
            {
                fOAEP = true;
            }

#if NETSTANDARD1_4
            RSAEncryptionPadding padding = RSAEncryptionPadding.Pkcs1;
            if (Algorithm.Equals(SecurityAlgorithms.RsaOAEP, StringComparison.Ordinal))
            {
                padding = RSAEncryptionPadding.OaepSHA1;
            }
            else if (Algorithm.Equals(SecurityAlgorithms.RsaOAEP256, StringComparison.Ordinal))
            {
                padding = RSAEncryptionPadding.OaepSHA256;
            }

            try
            {
                if (_rsa != null)
                    return _rsa.Encrypt(keyToWrap, padding);
                else if (_rsaCryptoServiceProviderProxy != null)
                    return _rsaCryptoServiceProviderProxy.Encrypt(keyToWrap, fOAEP);
            }
            catch (Exception ex)
            {
                throw LogHelper.LogExceptionMessage(new SecurityTokenKeyWrapException(string.Format(CultureInfo.InvariantCulture, LogMessages.IDX10658, ex)));
            }
#else
            try
            {
                if (_rsaCryptoServiceProvider != null)
                    return _rsaCryptoServiceProvider.Encrypt(keyToWrap, fOAEP);
                else if (_rsaCryptoServiceProviderProxy != null)
                    return _rsaCryptoServiceProviderProxy.Encrypt(keyToWrap, fOAEP);
            }
            catch (Exception ex)
            {
                throw LogHelper.LogExceptionMessage(new SecurityTokenKeyWrapException(string.Format(CultureInfo.InvariantCulture, LogMessages.IDX10658, ex)));
            }
#endif

            throw LogHelper.LogExceptionMessage(new InvalidOperationException(LogMessages.IDX10644));
        }
    }
}
