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
using System.Runtime.CompilerServices;
using System.Security.Cryptography;
using Microsoft.IdentityModel.Logging;

namespace Microsoft.IdentityModel.Tokens
{
    /// <summary>
    /// Provides signing and verifying operations using a <see cref="SymmetricSecurityKey"/> and specifying an algorithm.
    /// </summary>
    public class SymmetricSignatureProvider : SignatureProvider
    {
        private static byte[] s_bytesA = new byte[] { 0, 1, 2, 3, 4, 5, 6, 7, 8, 9, 10, 11, 12, 13, 14, 15, 16, 17, 18, 19, 20, 21, 22, 23, 24, 25, 26, 27, 28, 29, 30, 31 };
        private static byte[] s_bytesB = new byte[] { 31, 30, 29, 28, 27, 26, 25, 24, 23, 22, 21, 20, 19, 18, 17, 16, 15, 14, 13, 12, 11, 10, 9, 8, 7, 6, 5, 4, 3, 2, 1, 0 };
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
        /// <exception cref="ArgumentOutOfRangeException">'<see cref="SecurityKey"/>.KeySize' is smaller than <see cref="SymmetricSignatureProvider.MinimumSymmetricKeySizeInBits"/>.</exception>
        /// <exception cref="InvalidOperationException"><see cref="SymmetricSignatureProvider.GetKeyedHashAlgorithm"/> throws.</exception>
        /// <exception cref="InvalidOperationException"><see cref="SymmetricSignatureProvider.GetKeyedHashAlgorithm"/> returns null.</exception>
        public SymmetricSignatureProvider(SecurityKey key, string algorithm)
            : base(key, algorithm)
        {
            if (key == null)
                throw LogHelper.LogArgumentNullException("key");

            if (!key.IsSupportedAlgorithm(algorithm))
                throw LogHelper.LogArgumentException<ArgumentException>(nameof(algorithm), LogMessages.IDX10640, (algorithm ?? "null"));

            if (key.KeySize < MinimumSymmetricKeySizeInBits)
                throw LogHelper.LogArgumentException<ArgumentOutOfRangeException>("key.KeySize", LogMessages.IDX10603, (algorithm ?? "null"), MinimumSymmetricKeySizeInBits, key.KeySize);

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
                throw LogHelper.LogException<InvalidOperationException>(ex, LogMessages.IDX10634, key, (algorithm ?? "null"));
            }

            if (_keyedHash == null)
                throw LogHelper.LogArgumentException<ArgumentOutOfRangeException>(nameof(key), LogMessages.IDX10641, key);
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
                    throw LogHelper.LogArgumentException<ArgumentOutOfRangeException>("value", LogMessages.IDX10628, DefaultMinimumSymmetricKeySizeInBits);

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
                throw LogHelper.LogArgumentNullException("algorithm");

            if (key == null)
                throw LogHelper.LogArgumentNullException("key");

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
                    throw LogHelper.LogArgumentException<ArgumentOutOfRangeException>(nameof(algorithm), LogMessages.IDX10640, algorithm);
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
                throw LogHelper.LogArgumentNullException("input");

            if (input.Length == 0)
                throw LogHelper.LogException<ArgumentException>(LogMessages.IDX10624);

            if (_disposed)
                throw LogHelper.LogException<ObjectDisposedException>(GetType().ToString());

            if (_keyedHash == null)
                throw LogHelper.LogException<ArgumentNullException>(LogMessages.IDX10623);

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
                throw LogHelper.LogArgumentNullException(nameof(input));

            if (signature == null)
                throw LogHelper.LogArgumentNullException(nameof(signature));

            if (input.Length == 0)
                throw LogHelper.LogException<ArgumentException>(LogMessages.IDX10625);

            if (signature.Length == 0)
                throw LogHelper.LogException<ArgumentException>(LogMessages.IDX10626);

            if (_disposed)
                throw LogHelper.LogException<ObjectDisposedException>(typeof(SymmetricSignatureProvider).ToString());

            if (_keyedHash == null)
                throw LogHelper.LogException<ArgumentNullException>(LogMessages.IDX10623);

            IdentityModelEventSource.Logger.WriteInformation(LogMessages.IDX10643, input);
            return AreEqual(signature, _keyedHash.ComputeHash(input));
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

        /// <summary>
        /// Compares two byte arrays for equality. Hash size is fixed normally it is 32 bytes.
        /// The attempt here is to take the same time if an attacker shortens the signature OR changes some of the signed contents.
        /// </summary>
        /// <param name="a">
        /// One set of bytes to compare.
        /// </param>
        /// <param name="b">
        /// The other set of bytes to compare with.
        /// </param>
        /// <returns>
        /// true if the bytes are equal, false otherwise.
        /// </returns>
        [MethodImpl(MethodImplOptions.NoOptimization | MethodImplOptions.NoInlining)]
        private static bool AreEqual(byte[] a, byte[] b)
        {
            int result = 0;
            byte[] a1, a2;

            if (((null == a) || (null == b))
            || (a.Length != b.Length))
            {
                a1 = s_bytesA; 
                a2 = s_bytesB;
            }
            else
            {
                a1 = a; 
                a2 = b;
            }

            for (int i = 0; i < a1.Length; i++)
            {
                result |= a1[i] ^ a2[i];
            }

            return result == 0;
        }
    }
}
