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
using System.Globalization;

namespace Microsoft.IdentityModel.Tokens
{
    /// <summary>
    /// Provides signing and verifying operations using a <see cref="SymmetricSecurityKey"/> and specifying an algorithm.
    /// </summary>
    public class SymmetricSignatureProvider : SignatureProvider
    {
        private bool _disposed;
        private KeyedHashAlgorithm _keyedHash;

        /// <summary>
        /// This is the minimum <see cref="SymmetricSecurityKey"/>.KeySize when creating and verifying signatures.
        /// </summary>
        public static readonly int DefaultMinimumSymmetricKeySizeInBits = 128;

        private int _minimumSymmetricKeySizeInBits = DefaultMinimumSymmetricKeySizeInBits;

        /// <summary>
        /// Initializes a new instance of the <see cref="SymmetricSignatureProvider"/> class that uses an <see cref="SecurityKey"/> to create and / or verify signatures over a array of bytes.
        /// </summary>
        /// <param name="key">The <see cref="SecurityKey"/> that will be used for signature operations.</param>
        /// <param name="algorithm">The signature algorithm to use.</param>
        /// <exception cref="ArgumentNullException">'key' is null.</exception>
        /// <exception cref="ArgumentNullException">'algorithm' is null.</exception>
        /// <exception cref="ArgumentException">'algorithm' contains only whitespace.</exception>
        /// <exception cref="ArgumentException">If <see cref="SecurityKey"/> and algorithm pair are not supported.</exception>
        /// <exception cref="ArgumentOutOfRangeException">'<see cref="SecurityKey"/>.KeySize' is smaller than <see cref="SymmetricSignatureProvider.MinimumSymmetricKeySizeInBits"/>.</exception>
        /// <exception cref="InvalidOperationException"><see cref="SymmetricSignatureProvider.GetKeyedHashAlgorithm"/> throws.</exception>
        /// <exception cref="InvalidOperationException"><see cref="SymmetricSignatureProvider.GetKeyedHashAlgorithm"/> returns null.</exception>
        public SymmetricSignatureProvider(SecurityKey key, string algorithm)
            : base(key, algorithm)
        {
            if (key == null)
                throw LogHelper.LogExceptionMessage(new ArgumentNullException("key", String.Format(CultureInfo.InvariantCulture, LogMessages.IDX10000, "key"))); 

            if (!key.CryptoProviderFactory.IsSupportedAlgorithm(algorithm, key))
                throw LogHelper.LogExceptionMessage(new ArgumentException(String.Format(CultureInfo.InvariantCulture, LogMessages.IDX10634, (algorithm ?? "null"), key), nameof(algorithm)));

            if (key.KeySize < MinimumSymmetricKeySizeInBits)
                throw LogHelper.LogExceptionMessage(new ArgumentOutOfRangeException("key.KeySize", String.Format(CultureInfo.InvariantCulture, LogMessages.IDX10603, (algorithm ?? "null"), MinimumSymmetricKeySizeInBits, key.KeySize)));

            try
            {
                byte[] keyBytes = null;

                SymmetricSecurityKey symmetricSecurityKey = key as SymmetricSecurityKey;
                if (symmetricSecurityKey != null)
                    keyBytes = symmetricSecurityKey.Key;
                else
                {
                    JsonWebKey jsonWebKey = key as JsonWebKey;
                    if (jsonWebKey != null && jsonWebKey.K != null)
                        keyBytes = Base64UrlEncoder.DecodeBytes(jsonWebKey.K);
                }

                _keyedHash = GetKeyedHashAlgorithm(algorithm, keyBytes);
            }
            catch (Exception ex)
            {
                throw LogHelper.LogExceptionMessage(new InvalidOperationException(String.Format(CultureInfo.InvariantCulture, LogMessages.IDX10634, (algorithm ?? "null"), key), ex));
            }

            if (_keyedHash == null)
                throw LogHelper.LogExceptionMessage(new ArgumentOutOfRangeException(nameof(key), String.Format(CultureInfo.InvariantCulture, LogMessages.IDX10641, key)));
        }

        /// <summary>
        /// Gets or sets the minimum <see cref="SymmetricSecurityKey"/>.KeySize"/>.
        /// </summary>
        /// <exception cref="ArgumentOutOfRangeException">'value' is smaller than <see cref="DefaultMinimumSymmetricKeySizeInBits"/>.</exception>
        public int MinimumSymmetricKeySizeInBits
        {
            get
            {
                return _minimumSymmetricKeySizeInBits;
            }

            set
            {
                if (value < DefaultMinimumSymmetricKeySizeInBits)
                    throw LogHelper.LogExceptionMessage(new ArgumentOutOfRangeException("value", String.Format(CultureInfo.InvariantCulture, LogMessages.IDX10628, DefaultMinimumSymmetricKeySizeInBits)));

                _minimumSymmetricKeySizeInBits = value;
            }
        }

        /// <summary>
        /// Returns the <see cref="KeyedHashAlgorithm"/>.
        /// </summary>
        /// <param name="algorithm">The hash algorithm to use to create the hash value.</param>
        /// <param name="key">The byte array of the key.</param>
        /// <returns></returns>
        protected virtual KeyedHashAlgorithm GetKeyedHashAlgorithm(string algorithm, byte[] key)
        {
            if (string.IsNullOrWhiteSpace(algorithm))
                throw LogHelper.LogExceptionMessage(new ArgumentNullException("algorithm", String.Format(CultureInfo.InvariantCulture, LogMessages.IDX10000, "algorithm"))); 

            if (key == null)
                throw LogHelper.LogExceptionMessage(new ArgumentNullException("key", String.Format(CultureInfo.InvariantCulture, LogMessages.IDX10000, "key"))); 

            switch (algorithm)
            {
                case SecurityAlgorithms.HmacSha256Signature:
                case SecurityAlgorithms.HmacSha256:
                    return new HMACSHA256(key);

                case SecurityAlgorithms.HmacSha384Signature:
                case SecurityAlgorithms.HmacSha384:
                    return new HMACSHA384(key);

                case SecurityAlgorithms.HmacSha512Signature:
                case SecurityAlgorithms.HmacSha512:
                    return new HMACSHA512(key);

                default:
                    throw LogHelper.LogExceptionMessage(new ArgumentOutOfRangeException(nameof(algorithm), String.Format(CultureInfo.InvariantCulture, LogMessages.IDX10640, algorithm)));
            }
        }

        /// <summary>
        /// Produces a signature over the 'input' using the <see cref="SymmetricSecurityKey"/> and 'algorithm' passed to <see cref="SymmetricSignatureProvider( SecurityKey, string )"/>.
        /// </summary>
        /// <param name="input">The bytes to sign.</param>
        /// <returns>Signed bytes</returns>
        /// <exception cref="ArgumentNullException">'input' is null. </exception>
        /// <exception cref="ArgumentException">'input.Length' == 0. </exception>
        /// <exception cref="ObjectDisposedException"><see cref="Dispose(bool)"/> has been called.</exception>
        /// <exception cref="InvalidOperationException"><see cref="KeyedHashAlgorithm"/> is null. This can occur if a derived type deletes it or does not create it.</exception>
        public override byte[] Sign(byte[] input)
        {
            if (input == null)
                throw LogHelper.LogExceptionMessage(new ArgumentNullException("input", String.Format(CultureInfo.InvariantCulture, LogMessages.IDX10000, "input"))); 

            if (input.Length == 0)
                throw LogHelper.LogExceptionMessage(new ArgumentException(LogMessages.IDX10624));

            if (_disposed)
                throw LogHelper.LogExceptionMessage(new ObjectDisposedException(GetType().ToString()));

            if (_keyedHash == null)
                throw LogHelper.LogExceptionMessage(new InvalidOperationException(LogMessages.IDX10623));

            IdentityModelEventSource.Logger.WriteInformation(LogMessages.IDX10642, input);

            return _keyedHash.ComputeHash(input);
        }

        /// <summary>
        /// Verifies that a signature created over the 'input' matches the signature. Using <see cref="SymmetricSecurityKey"/> and 'algorithm' passed to <see cref="SymmetricSignatureProvider( SecurityKey, string )"/>.
        /// </summary>
        /// <param name="input">The bytes to verify.</param>
        /// <param name="signature">signature to compare against.</param>
        /// <returns>true if computed signature matches the signature parameter, false otherwise.</returns>
        /// <exception cref="ArgumentNullException">'input' is null.</exception>
        /// <exception cref="ArgumentNullException">'signature' is null.</exception>
        /// <exception cref="ArgumentException">'input.Length' == 0.</exception>
        /// <exception cref="ArgumentException">'signature.Length' == 0. </exception>
        /// <exception cref="ObjectDisposedException"><see cref="Dispose(bool)"/> has been called.</exception>
        /// <exception cref="InvalidOperationException">If the internal <see cref="KeyedHashAlgorithm"/> is null. This can occur if a derived type deletes it or does not create it.</exception>
        public override bool Verify(byte[] input, byte[] signature)
        {
            if (input == null)
                throw LogHelper.LogExceptionMessage(new ArgumentNullException(nameof(input), String.Format(CultureInfo.InvariantCulture, LogMessages.IDX10000, nameof(input)))); 

            if (signature == null)
                throw LogHelper.LogExceptionMessage(new ArgumentNullException(nameof(signature), String.Format(CultureInfo.InvariantCulture, LogMessages.IDX10000, nameof(signature)))); 

            if (input.Length == 0)
                throw LogHelper.LogExceptionMessage(new ArgumentException(LogMessages.IDX10625));

            if (signature.Length == 0)
                throw LogHelper.LogExceptionMessage(new ArgumentException(LogMessages.IDX10626));

            if (_disposed)
                throw LogHelper.LogExceptionMessage(new ObjectDisposedException(typeof(SymmetricSignatureProvider).ToString()));

            if (_keyedHash == null)
                throw LogHelper.LogExceptionMessage(new InvalidOperationException(LogMessages.IDX10623));

            IdentityModelEventSource.Logger.WriteInformation(LogMessages.IDX10643, input);
            return Utility.AreEqual(signature, _keyedHash.ComputeHash(input));
        }

        #region IDisposable Members

        /// <summary>
        /// Disposes of internal components.
        /// </summary>
        /// <param name="disposing">true, if called from Dispose(), false, if invoked inside a finalizer.</param>
        protected override void Dispose(bool disposing)
        {
            if (!_disposed)
            {
                _disposed = true;

                if (disposing)
                {
                    if (_keyedHash != null)
                    {
                        _keyedHash.Dispose();
                        _keyedHash = null;
                    }
                }
            }
        }

        #endregion
    }
}
