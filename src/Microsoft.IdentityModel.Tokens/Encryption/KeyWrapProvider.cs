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
using System.Globalization;
using System.Security.Cryptography;
using Microsoft.IdentityModel.Logging;

namespace Microsoft.IdentityModel.Tokens
{
    /// <summary>
    /// Provides Wrap key and Unwrap key services.
    /// </summary>
    public class KeyWrapProvider
    {
        private static readonly byte[] _defaultIv = new byte[] { 0xA6, 0xA6, 0xA6, 0xA6, 0xA6, 0xA6, 0xA6, 0xA6 };
        private static readonly int BlockSizeInBits = 64;
        private static readonly int BlockSizeInBytes = BlockSizeInBits >> 3;
        private static object encryptorLock = new object();
        private static object decryptorLock = new object();

        private SymmetricAlgorithm _symmetricAlgorithm;
        private ICryptoTransform _symmetricAlgorithmEncryptor;
        private ICryptoTransform _symmetricAlgorithmDecryptor;

        /// <summary>
        /// Initializes a new instance of the <see cref="KeyWrapProvider"/> class used for wrap key and unwrap key.
        /// <param name="key">The <see cref="SecurityKey"/> that will be used for crypto operations.</param>
        /// <param name="algorithm">The KeyWrap algorithm to apply.</param>
        /// <exception cref="ArgumentNullException">'key' is null.</exception>
        /// <exception cref="ArgumentNullException">'algorithm' is null.</exception>
        /// <exception cref="ArgumentException">If <see cref="SecurityKey"/> and algorithm pair are not supported.</exception>
        /// <exception cref="InvalidOperationException"><see cref="KeyWrapProvider.GetSymmetricAlgorithm"/> throws.</exception>
        /// </summary>
        public KeyWrapProvider(SecurityKey key, string algorithm)
        {
            if (key == null)
                throw LogHelper.LogArgumentNullException(nameof(key));

            if (string.IsNullOrEmpty(algorithm))
                throw LogHelper.LogArgumentNullException(nameof(algorithm));

            if (!IsSupportedAlgorithm(key, algorithm))
                throw LogHelper.LogExceptionMessage(new ArgumentException(String.Format(CultureInfo.InvariantCulture, LogMessages.IDX10661, algorithm, key)));

            Algorithm = algorithm;
            Key = key;

            _symmetricAlgorithm = GetSymmetricAlgorithm();
        }

        /// <summary>
        /// Returns the <see cref="SymmetricAlgorithm"/>.
        /// </summary>
        /// <returns></returns>
        /// <exception cref="ArgumentException">The <see cref="SecurityKey"/> cannot be converted to byte array</exception>
        /// <exception cref="ArgumentOutOfRangeException">The keysize doesn't match the algorithm.</exception>
        /// <exception cref="ArgumentOutOfRangeException">The algorithm doesn't support algorithm.</exception>
        /// <exception cref="InvalidOperationException">Failed to create symmetric algorithm with provided key and algorithm.</exception>
        protected virtual SymmetricAlgorithm GetSymmetricAlgorithm()
        {
            byte[] keyBytes = null;

            SymmetricSecurityKey symmetricSecurityKey = Key as SymmetricSecurityKey;
            if (symmetricSecurityKey != null)
                keyBytes = symmetricSecurityKey.Key;
            else
            {
                JsonWebKey jsonWebKey = Key as JsonWebKey;
                if (jsonWebKey != null && jsonWebKey.K != null && jsonWebKey.Kty == JsonWebAlgorithmsKeyTypes.Octet)
                    keyBytes = Base64UrlEncoder.DecodeBytes(jsonWebKey.K);
            }

            if (keyBytes == null)
                throw LogHelper.LogExceptionMessage(new ArgumentException(string.Format(CultureInfo.InvariantCulture, LogMessages.IDX10657, Key.GetType())));

            ValidateKeySize(keyBytes, Algorithm);

            try
            {
                // Create the AES provider
                _symmetricAlgorithm = Aes.Create();
                _symmetricAlgorithm.Mode = CipherMode.ECB;
                _symmetricAlgorithm.Padding = PaddingMode.None;
                _symmetricAlgorithm.KeySize = keyBytes.Length * 8;
                _symmetricAlgorithm.Key = keyBytes;

                // Set the AES IV to Zeroes
                var aesIv = new byte[_symmetricAlgorithm.BlockSize >> 3];
                aesIv.Zero();
                _symmetricAlgorithm.IV = aesIv;
            }
            catch (Exception ex)
            {
                throw LogHelper.LogExceptionMessage(new InvalidOperationException(String.Format(CultureInfo.InvariantCulture, LogMessages.IDX10663, Key, Algorithm), ex));
            }

            return _symmetricAlgorithm;
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

        private static byte[] GetBytes(ulong i)
        {
            byte[] temp = BitConverter.GetBytes(i);

            if (BitConverter.IsLittleEndian)
            {
                Array.Reverse(temp);
            }

            return temp;
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

            if (!(algorithm.Equals(SecurityAlgorithms.Aes128KW, StringComparison.Ordinal) || algorithm.Equals(SecurityAlgorithms.Aes256KW, StringComparison.Ordinal)))
                return false;

            if (key is SymmetricSecurityKey)
                return true;

            var jsonWebKey = key as JsonWebKey;
            if (jsonWebKey != null)
                return (jsonWebKey.K != null && jsonWebKey.Kty == JsonWebAlgorithmsKeyTypes.Octet);

            return false;
        }

        /// <summary>
        /// Unwrap the wrappedKey
        /// </summary>
        /// <param name="wrappedKey">the wrapped key to unwrap</param>
        /// <returns>Unwrap wrapped key</returns>
        /// <exception cref="ArgumentNullException">'wrappedKey' is null or empty.</exception>
        /// <exception cref="ArgumentException">The lenth of wrappedKey must be a multiple of 64 bits.</exception>
        /// <exception cref="KeyWrapUnwrapException">Failed to unwrap the wrappedKey.</exception>
        public virtual byte[] UnwrapKey(byte[] wrappedKey)
        {
            if (wrappedKey == null || wrappedKey.Length == 0)
                throw LogHelper.LogArgumentNullException(nameof(wrappedKey));

            if (wrappedKey.Length % 8 != 0)
                throw LogHelper.LogExceptionMessage(new ArgumentException(nameof(wrappedKey), string.Format(CultureInfo.InvariantCulture, LogMessages.IDX10664, wrappedKey.Length << 3)));

            try
            {
                return UnwrapKeyPrivate(wrappedKey, 0, wrappedKey.Length);
            }
            catch (Exception ex)
            {
                throw LogHelper.LogExceptionMessage(new KeyWrapUnwrapException(string.Format(CultureInfo.InvariantCulture, LogMessages.IDX10659, ex)));
            }
        }

        private byte[] UnwrapKeyPrivate(byte[] inputBuffer, int inputOffset, int inputCount)
        {
            /*
                1) Initialize variables.

                    Set A = C[0]
                    For i = 1 to n
                        R[i] = C[i]

                2) Compute intermediate values.

                    For j = 5 to 0
                        For i = n to 1
                            B = AES-1(K, (A ^ t) | R[i]) where t = n*j+i
                            A = MSB(64, B)
                            R[i] = LSB(64, B)

                3) Output results.

                If A is an appropriate initial value (see 2.2.3),
                Then
                    For i = 1 to n
                        P[i] = R[i]
                Else
                    Return an error
            */

            byte[] iv = _defaultIv.Clone() as byte[];

            // A = C[0]
            byte[] a = new byte[BlockSizeInBytes];

            Array.Copy(inputBuffer, inputOffset, a, 0, BlockSizeInBytes);

            // The number of input blocks
            var n = (inputCount - BlockSizeInBytes) >> 3;

            // The set of input blocks
            byte[] r = new byte[n << 3];

            Array.Copy(inputBuffer, inputOffset + BlockSizeInBytes, r, 0, inputCount - BlockSizeInBytes);

            if (_symmetricAlgorithmDecryptor == null)
            {
                lock (decryptorLock)
                {
                    if (_symmetricAlgorithmDecryptor == null)
                        _symmetricAlgorithmDecryptor = _symmetricAlgorithm.CreateDecryptor();
                }
            }

            byte[] block = new byte[16];

            // Calculate intermediate values
            for (var j = 5; j >= 0; j--)
            {
                for (var i = n; i > 0; i--)
                {
                    // T = ( n * j ) + i
                    var t = (ulong)((n * j) + i);

                    // B = AES-1(K, (A ^ t) | R[i] )

                    // First, A = ( A ^ t )
                    a.Xor(GetBytes(t), true);

                    // Second, block = ( A | R[i] )
                    Array.Copy(a, block, BlockSizeInBytes);
                    Array.Copy(r, (i - 1) << 3, block, BlockSizeInBytes, BlockSizeInBytes);

                    // Third, b = AES-1( block )
                    var b = _symmetricAlgorithmDecryptor.TransformFinalBlock(block, 0, 16);

                    // A = MSB(64, B)
                    Array.Copy(b, a, BlockSizeInBytes);

                    // R[i] = LSB(64, B)
                    Array.Copy(b, BlockSizeInBytes, r, (i - 1) << 3, BlockSizeInBytes);
                }
            }

            if (a.SequenceEqualConstantTime(iv))
            {
                var c = new byte[n << 3];

                for (var i = 0; i < n; i++)
                {
                    Array.Copy(r, i << 3, c, i << 3, 8);
                }

                return c;
            }
            else
            {
                throw LogHelper.LogException<InvalidOperationException>(LogMessages.IDX10665);
            }
        }

        private void ValidateKeySize(byte[] key, string algorithm)
        {
            if (SecurityAlgorithms.Aes128KW.Equals(algorithm, StringComparison.Ordinal))
            {
                if (key.Length != 16)
                    throw LogHelper.LogExceptionMessage(new ArgumentOutOfRangeException("key.KeySize", string.Format(CultureInfo.InvariantCulture, LogMessages.IDX10662, SecurityAlgorithms.Aes128KW, 128, Key.KeyId, key.Length << 3)));

                return;
            }

            if (SecurityAlgorithms.Aes256KW.Equals(algorithm, StringComparison.Ordinal))
            {
                if (key.Length != 32)
                    throw LogHelper.LogExceptionMessage(new ArgumentOutOfRangeException("key.KeySize", string.Format(CultureInfo.InvariantCulture, LogMessages.IDX10662, SecurityAlgorithms.Aes256KW, 256, Key.KeyId, key.Length << 3)));

                return;
            }

            throw LogHelper.LogExceptionMessage(new ArgumentOutOfRangeException(nameof(algorithm), String.Format(CultureInfo.InvariantCulture, LogMessages.IDX10652, algorithm)));
        }

        /// <summary>
        /// Wrap the 'keyToWrap'
        /// </summary>
        /// <param name="keyToWrap">the key to be wrapped</param>
        /// <returns>The wrapped key</returns>
        /// <exception cref="ArgumentNullException">'keyToWrap' is null or empty.</exception>
        /// <exception cref="ArgumentException">The length of keyToWrap must be a multiple of 64 bits.</exception>
        /// <exception cref="KeyWrapWrapException">Failed to wrap the keyToWrap.</exception>
        public virtual byte[] WrapKey(byte[] keyToWrap)
        {
            if (keyToWrap == null || keyToWrap.Length == 0)
                throw LogHelper.LogArgumentNullException(nameof(keyToWrap));

            if (keyToWrap.Length %8 != 0)
                throw LogHelper.LogExceptionMessage(new ArgumentException(nameof(keyToWrap), string.Format(CultureInfo.InvariantCulture, LogMessages.IDX10664, keyToWrap.Length << 3)));

            try
            {
                return WrapKeyPrivate(keyToWrap, 0, keyToWrap.Length);
            }
            catch (Exception ex)
            {
                throw LogHelper.LogExceptionMessage(new KeyWrapWrapException(string.Format(CultureInfo.InvariantCulture, LogMessages.IDX10658, ex)));
            }
        }

        private byte[] WrapKeyPrivate(byte[] inputBuffer, int inputOffset, int inputCount)
        {
            /*
               1) Initialize variables.

                   Set A = IV, an initial value (see 2.2.3)
                   For i = 1 to n
                       R[i] = P[i]

               2) Calculate intermediate values.

                   For j = 0 to 5
                       For i=1 to n
                           B = AES(K, A | R[i])
                           A = MSB(64, B) ^ t where t = (n*j)+i
                           R[i] = LSB(64, B)

               3) Output the results.

                   Set C[0] = A
                   For i = 1 to n
                       C[i] = R[i]
            */

            byte[] iv = _defaultIv.Clone() as byte[];

            // The default initialization vector from RFC3394
            byte[] a = iv;

            // The number of input blocks
            var n = inputCount >> 3;

            // The set of input blocks
            byte[] r = new byte[n << 3];

            Array.Copy(inputBuffer, inputOffset, r, 0, inputCount);

            if (_symmetricAlgorithmEncryptor == null)
            {
                lock (encryptorLock)
                {
                    if (_symmetricAlgorithmEncryptor == null)
                        _symmetricAlgorithmEncryptor = _symmetricAlgorithm.CreateEncryptor();
                }
            }

            byte[] block = new byte[16];

            // Calculate intermediate values
            for (var j = 0; j < 6; j++)
            {
                for (var i = 0; i < n; i++)
                {
                    // T = ( n * j ) + i
                    var t = (ulong)((n * j) + i + 1);

                    // B = AES( K, A | R[i] )

                    // First, block = A | R[i]
                    Array.Copy(a, block, a.Length);
                    Array.Copy(r, i << 3, block, 64 >> 3, 64 >> 3);

                    // Second, AES( K, block )
                    var b = _symmetricAlgorithmEncryptor.TransformFinalBlock(block, 0, 16);

                    // A = MSB( 64, B )
                    Array.Copy(b, a, 64 >> 3);

                    // A = A ^ t
                    a.Xor(GetBytes(t), true);

                    // R[i] = LSB( 64, B )
                    Array.Copy(b, 64 >> 3, r, i << 3, 64 >> 3);
                }
            }

            var c = new byte[(n + 1) << 3];

            Array.Copy(a, c, a.Length);

            for (var i = 0; i < n; i++)
            {
                Array.Copy(r, i << 3, c, (i + 1) << 3, 8);
            }

            return c;
        }
    }
}
