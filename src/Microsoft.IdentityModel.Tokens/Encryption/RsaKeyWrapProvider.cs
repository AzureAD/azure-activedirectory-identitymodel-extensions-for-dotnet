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
    public class RsaKeyWrapProvider : KeyWrapProvider
    {
#if NETSTANDARD1_4
        private RSA _rsa;
#else
        private RSACryptoServiceProvider _rsaCryptoServiceProvider;
#endif
        private bool _disposeRsa;
        private RSACryptoServiceProviderProxy _rsaCryptoServiceProviderProxy;
        private bool _disposed = false;

        /// <summary>
        /// Initializes a new instance of the <see cref="RsaKeyWrapProvider"/> class used for wrap key and unwrap key.
        /// <param name="key">The <see cref="SecurityKey"/> that will be used for crypto operations.</param>
        /// <param name="algorithm">The KeyWrap algorithm to apply.</param>
        /// <param name="willUnwrap">Whether this <see cref="RsaKeyWrapProvider"/> is required to create decrypts then set this to true.</param>
        /// <exception cref="ArgumentNullException">'key' is null.</exception>
        /// <exception cref="ArgumentNullException">'algorithm' is null.</exception>
        /// <exception cref="ArgumentOutOfRangeException">The keysize doesn't match the algorithm.</exception>
        /// <exception cref="ArgumentOutOfRangeException">The <see cref="SecurityKey"/>  is not supported.</exception>
        /// <exception cref="ArgumentException">If <see cref="SecurityKey"/> and algorithm pair are not supported.</exception>
        /// <exception cref="InvalidOperationException">Failed to create RSA algorithm with provided key and algorithm.</exception>
        /// </summary>
        public RsaKeyWrapProvider(SecurityKey key, string algorithm, bool willUnwrap)
        {
            if (key == null)
                throw LogHelper.LogArgumentNullException(nameof(key));

            if (string.IsNullOrEmpty(algorithm))
                throw LogHelper.LogArgumentNullException(nameof(algorithm));

            if (!IsSupportedAlgorithm(key, algorithm))
                throw LogHelper.LogExceptionMessage(new ArgumentException(string.Format(CultureInfo.InvariantCulture, LogMessages.IDX10661, algorithm, key)));

            Algorithm = algorithm;
            Key = key;

            RsaAlgorithm rsaAlgorithm = Utility.ResolveRsaAlgorithm(key, algorithm, willUnwrap);
#if NETSTANDARD1_4
            if (rsaAlgorithm != null)
            {
                if (rsaAlgorithm.rsa != null)
                {
                    _rsa = rsaAlgorithm.rsa;
                    _disposeRsa = rsaAlgorithm.dispose;
                }
                else if (rsaAlgorithm.rsaCryptoServiceProviderProxy != null)
                {
                    _rsaCryptoServiceProviderProxy = rsaAlgorithm.rsaCryptoServiceProviderProxy;
                    _disposeRsa = rsaAlgorithm.dispose;
                }
                else
                    throw LogHelper.LogExceptionMessage(new InvalidOperationException(string.Format(CultureInfo.InvariantCulture, LogMessages.IDX10661, algorithm, key)));
            }
            else
                throw LogHelper.LogExceptionMessage(new InvalidOperationException(string.Format(CultureInfo.InvariantCulture, LogMessages.IDX10661, algorithm, key)));
#else
            if (rsaAlgorithm != null)
            {
                if (rsaAlgorithm.rsaCryptoServiceProvider != null)
                {
                    _rsaCryptoServiceProvider = rsaAlgorithm.rsaCryptoServiceProvider;
                    _disposeRsa = rsaAlgorithm.dispose;
                }
                else if (rsaAlgorithm.rsaCryptoServiceProviderProxy != null)
                {
                    _rsaCryptoServiceProviderProxy = rsaAlgorithm.rsaCryptoServiceProviderProxy;
                    _disposeRsa = rsaAlgorithm.dispose;
                }
                else
                      throw LogHelper.LogExceptionMessage(new InvalidOperationException(string.Format(CultureInfo.InvariantCulture, LogMessages.IDX10661, algorithm, key)));
            }
            else
                throw LogHelper.LogExceptionMessage(new InvalidOperationException(string.Format(CultureInfo.InvariantCulture, LogMessages.IDX10661, algorithm, key)));
#endif
        }

        /// <summary>
        /// Gets the KeyWrap algorithm that is being used.
        /// </summary>
        public override string Algorithm { get; }

        /// <summary>
        /// Gets or sets a user context for a <see cref="KeyWrapProvider"/>.
        /// </summary>
        /// <remarks>This is null by default. This can be used by runtimes or for extensibility scenarios.</remarks>
        public override string Context { get; set; }

        /// <summary>
        /// Gets the <see cref="SecurityKey"/> that is being used.
        /// </summary>
        public override SecurityKey Key { get; }

        /// <summary>
        /// Disposes of internal components.
        /// </summary>
        /// <param name="disposing">true, if called from Dispose(), false, if invoked inside a finalizer.</param>
        protected override void Dispose(bool disposing)
        {
            if (!_disposed)
            {
                if (disposing)
                {
#if NETSTANDARD1_4
                    if (_rsa != null && _disposeRsa)
                        _rsa.Dispose();
#else
                    if (_rsaCryptoServiceProvider != null && _disposeRsa)
                        _rsaCryptoServiceProvider.Dispose();
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
        /// <returns>true if the algorithm is supported; otherwise, false.</returns>
        protected virtual bool IsSupportedAlgorithm(SecurityKey key, string algorithm)
        {
            if (key == null)
                return false;

            if (string.IsNullOrEmpty(algorithm))
                return false;

            if (key.KeySize < 2048)
            {
                return false;
            }

            if (algorithm.Equals(SecurityAlgorithms.RsaPKCS1, StringComparison.Ordinal)
                || algorithm.Equals(SecurityAlgorithms.RsaOAEP, StringComparison.Ordinal))
            {
                if (key as RsaSecurityKey != null)
                    return true;

                X509SecurityKey x509Key = key as X509SecurityKey;
                if (x509Key != null)
                {
#if NETSTANDARD1_4
                    if (x509Key.PublicKey as RSA != null)
                        return true;
#else
                    if (x509Key.PublicKey as RSACryptoServiceProvider != null)
                        return true;
#endif

                    return false;
                }

                var jsonWebKey = key as JsonWebKey;
                if (jsonWebKey != null && jsonWebKey.Kty == JsonWebAlgorithmsKeyTypes.RSA)
                    return true;
            }

            return false;
        }

        /// <summary>
        /// Unwrap the wrappedKey
        /// </summary>
        /// <param name="keyWrapContext"><see cref="KeyWrapContext"/></param>
        /// <returns>Unwrap wrapped key</returns>
        /// <exception cref="ArgumentNullException">'wrappedKey' is null or empty.</exception>
        /// <exception cref="ObjectDisposedException">If <see cref="RsaKeyWrapProvider.Dispose(bool)"/> has been called.</exception>
        /// <exception cref="SecurityTokenKeyWrapException">Failed to unwrap the wrappedKey.</exception>
        /// <exception cref="InvalidOperationException">If the internal RSA algorithm is null.</exception>
        public override byte[] UnwrapKey(KeyWrapContext keyWrapContext)
        {
            if (keyWrapContext.WrappedKey == null || keyWrapContext.WrappedKey.Length == 0)
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

            try
            {
                if (_rsa != null)
                    return _rsa.Decrypt(keyWrapContext.WrappedKey, padding);
                else if (_rsaCryptoServiceProviderProxy != null)
                    return _rsaCryptoServiceProviderProxy.Decrypt(keyWrapContext.WrappedKey, fOAEP);
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
                    return _rsaCryptoServiceProvider.Decrypt(keyWrapContext.WrappedKey, fOAEP);
                else if (_rsaCryptoServiceProviderProxy != null)
                    return _rsaCryptoServiceProviderProxy.Decrypt(keyWrapContext.WrappedKey, fOAEP);
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
        /// <returns>The wrapped key result</returns>
        /// <exception cref="ArgumentNullException">'keyToWrap' is null or empty.</exception>
        /// <exception cref="ObjectDisposedException">If <see cref="RsaKeyWrapProvider.Dispose(bool)"/> has been called.</exception>
        /// <exception cref="SecurityTokenKeyWrapException">Failed to wrap the keyToWrap.</exception>
        /// <exception cref="InvalidOperationException">If the internal RSA algorithm is null.</exception>
        public override KeyWrapContext WrapKey(byte[] keyToWrap)
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

            try
            {
                if (_rsa != null)
                {
                    KeyWrapContext result = new KeyWrapContext { WrappedKey = _rsa.Encrypt(keyToWrap, padding) };
                    return result;
                }
                else if (_rsaCryptoServiceProviderProxy != null)
                {
                    KeyWrapContext result = new KeyWrapContext { WrappedKey = _rsaCryptoServiceProviderProxy.Encrypt(keyToWrap, fOAEP) };
                    return result;
                }
            }
            catch (Exception ex)
            {
                throw LogHelper.LogExceptionMessage(new SecurityTokenKeyWrapException(string.Format(CultureInfo.InvariantCulture, LogMessages.IDX10658, ex)));
            }
#else
            try
            {
                if (_rsaCryptoServiceProvider != null)
                {
                    KeyWrapContext result = new KeyWrapContext { WrappedKey = _rsaCryptoServiceProvider.Encrypt(keyToWrap, fOAEP) };
                    return result;
                }
                else if (_rsaCryptoServiceProviderProxy != null)
                {
                    KeyWrapContext result = new KeyWrapContext { WrappedKey = _rsaCryptoServiceProviderProxy.Encrypt(keyToWrap, fOAEP) };
                    return result;
                }
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
