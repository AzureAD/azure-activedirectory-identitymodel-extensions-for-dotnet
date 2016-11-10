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
    public class RsaKeyWrapProvider : IDisposable
    {
        private RSACryptoServiceProvider _rsaCryptoServiceProvider;
        private bool _dispose;

        public RsaKeyWrapProvider(SecurityKey key, string algorithm, bool isDecrypt)
        {
            if (key == null)
                throw LogHelper.LogArgumentNullException(nameof(key));

            if (string.IsNullOrEmpty(algorithm))
                throw LogHelper.LogArgumentNullException(nameof(algorithm));

            if (!IsSupportedAlgorithm(key, algorithm))
                throw LogHelper.LogExceptionMessage(new ArgumentException(string.Format(CultureInfo.InvariantCulture, LogMessages.IDX10671, algorithm, key)));

            Algorithm = algorithm;
            Key = key;

            ResolveRsaAlgorithm(key, algorithm, isDecrypt);
            if (_rsaCryptoServiceProvider == null)
                throw LogHelper.LogExceptionMessage(new InvalidOperationException(string.Format(CultureInfo.InvariantCulture, LogMessages.IDX10672)));
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
            if (!_dispose)
            {
                if (disposing)
                {
                    if (_rsaCryptoServiceProvider != null)
                    {
                        _rsaCryptoServiceProvider.Dispose();
                        _rsaCryptoServiceProvider = null;
                    }

                    _dispose = true;
                }
            }
        }

        protected virtual void ResolveRsaAlgorithm(SecurityKey key, string algorithm, bool isDecrypt)
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
                    _dispose = true;
                }
                return;
            }

            JsonWebKey webKey = key as JsonWebKey;
            if (webKey.Kty == JsonWebAlgorithmsKeyTypes.RSA)
            {
                RSAParameters parameters = CreateRsaParametersFromJsonWebKey(webKey, isDecrypt);
                _rsaCryptoServiceProvider = new RSACryptoServiceProvider();
                (_rsaCryptoServiceProvider as RSA).ImportParameters(parameters);
                return;
            }

            throw LogHelper.LogExceptionMessage(new ArgumentOutOfRangeException(nameof(key), String.Format(CultureInfo.InvariantCulture, LogMessages.IDX10641, key)));
        }

        /// <summary>
        /// Answers if an algorithm is supported
        /// </summary>
        /// <param name="key">the <see cref="SecurityKey"/></param>
        /// <param name="algorithm">the algorithm to use</param>
        /// <returns>true if the algorithm is supported; otherwise, false.</returns>
        protected virtual bool IsSupportedAlgorithm(SecurityKey key, string algorithm)
        {
            if (key == null)
                return false;

            if (string.IsNullOrEmpty(algorithm))
                return false;

            if (algorithm.Equals(SecurityAlgorithms.RsaPKCS1, StringComparison.Ordinal) || algorithm.Equals(SecurityAlgorithms.RsaOAEP, StringComparison.Ordinal))
            {
                if (key is SymmetricSecurityKey)
                    return true;

                var jsonWebKey = key as JsonWebKey;
                if (jsonWebKey.Kty == JsonWebAlgorithmsKeyTypes.RSA)
                    return true;
            }

            return false;
        }

        /// <summary>
        /// Wrap the 'keyToWrap'
        /// </summary>
        /// <param name="keyToWrap">the key to be wrapped</param>
        /// <returns>The wrapped key</returns>
        public virtual byte[] WrapKey(byte[] keyToWrap)
        {
            bool fOAEP = false;
            if (Algorithm.Equals(SecurityAlgorithms.RsaOAEP, StringComparison.Ordinal))
            {
                fOAEP = true;
            }

            return _rsaCryptoServiceProvider.Encrypt(keyToWrap, fOAEP);
        }

        /// <summary>
        /// Unwrap the wrappedKey
        /// </summary>
        /// <param name="wrappedKey">the wrapped key to unwrap</param>
        /// <returns>Unwrap wrapped key</returns>
        public virtual byte[] UnwrapKey(byte[] wrappedKey)
        {
            bool fOAEP = false;
            if (Algorithm.Equals(SecurityAlgorithms.RsaOAEP, StringComparison.Ordinal))
            {
                fOAEP = true;
            }

            return _rsaCryptoServiceProvider.Decrypt(wrappedKey, fOAEP);
        }
    }
}
