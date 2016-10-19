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
    /// Provides authenticated encryption and decryption services.
    /// </summary>
    public class AuthenticatedEncryptionProvider
    {
        private struct AuthenticatedKeys
        {
            public SymmetricSecurityKey AesKey;
            public SymmetricSecurityKey HmacKey;
        }

        private AuthenticatedKeys _authenticatedkeys;
        private string _hashAlgorithm;
        private SymmetricSignatureProvider _symmetricSignatureProvider;

        /// <summary>
        /// Initializes a new instance of the <see cref="AuthenticatedEncryptionProvider"/> class used for encryption and decryption.
        /// <param name="key">The <see cref="SecurityKey"/> that will be used for crypto operations.</param>
        /// <param name="algorithm">The encryption algorithm to apply.</param>
        /// <exception cref="ArgumentNullException">'key' is null.</exception>
        /// <exception cref="ArgumentNullException">'algorithm' is null or whitespace.</exception>
        /// <exception cref="ArgumentOutOfRangeException">key size is not large enough.</exception>
        /// <exception cref="ArgumentException">'algorithm' is not supported.</exception>
        /// </summary>
        public AuthenticatedEncryptionProvider(SymmetricSecurityKey key, string algorithm)
        {
            if (key == null)
                throw LogHelper.LogArgumentNullException(nameof(key));

            if (string.IsNullOrWhiteSpace(algorithm))
                throw LogHelper.LogArgumentNullException(nameof(algorithm));

            ValidateKeySize(key.Key, algorithm);
            _authenticatedkeys = GetAlgorithmParameters(key, algorithm);
            _hashAlgorithm = GetHashAlgorithm(algorithm);

            // TODO - should we throw here?
            _symmetricSignatureProvider = key.CryptoProviderFactory.CreateForSigning(_authenticatedkeys.HmacKey, _hashAlgorithm) as SymmetricSignatureProvider;
            if (_symmetricSignatureProvider == null)
                throw LogHelper.LogExceptionMessage(new SecurityTokenDecryptionFailedException(string.Format(CultureInfo.InvariantCulture, LogMessages.IDX10649, Algorithm)));

            Key = key;
            Algorithm = algorithm;
        }

        /// <summary>
        /// Gets the encryption algorithm.
        /// </summary>
        public string Algorithm { get; private set; }

        /// <summary>
        /// Gets or sets a user context for a <see cref="AuthenticatedEncryptionProvider"/>.
        /// </summary>
        public string Context { get; set; }

        /// <summary>
        /// Gets the <see cref="SymmetricSecurityKey"/>.
        /// </summary>
        public SymmetricSecurityKey Key { get; private set; }

        /// <summary>
        /// Encrypts the 'plaintext'
        /// </summary>
        /// <param name="plaintext">the data to be encrypted.</param>
        /// <param name="authenticatedData">will be combined with iv and ciphertext to create an authenticationtag.</param>
        /// <returns><see cref="AuthenticatedEncryptionResult"/>containing ciphertext, iv, authenticationtag.</returns>
        /// <exception cref="ArgumentNullException">plaintext is null or empty.</exception>
        /// <exception cref="ArgumentNullException">authenticationData is null or empty.</exception>
        public virtual AuthenticatedEncryptionResult Encrypt(byte[] plaintext, byte[] authenticatedData)
        {
            if (plaintext == null || plaintext.Length == 0)
                throw LogHelper.LogArgumentNullException(nameof(plaintext));

            if (authenticatedData == null || authenticatedData.Length == 0)
                throw LogHelper.LogArgumentNullException(nameof(authenticatedData));

            Aes aes = Aes.Create();
            aes.Mode = CipherMode.CBC;
            aes.Padding = PaddingMode.PKCS7;
            aes.Key = _authenticatedkeys.AesKey.Key;

            AuthenticatedEncryptionResult result = new AuthenticatedEncryptionResult();
            result.Ciphertext = Utility.Transform(aes.CreateEncryptor(), plaintext, 0, plaintext.Length);
            result.Key = Key;
            result.InitializationVector = aes.IV;

            byte[] al = ConvertToBigEndian(authenticatedData.Length * 8);
            byte[] macBytes = new byte[authenticatedData.Length + result.InitializationVector.Length + result.Ciphertext.Length + al.Length];
            Array.Copy(authenticatedData, 0, macBytes, 0, authenticatedData.Length);
            Array.Copy(result.InitializationVector, 0, macBytes, authenticatedData.Length, result.InitializationVector.Length);
            Array.Copy(result.Ciphertext, 0, macBytes, authenticatedData.Length + result.InitializationVector.Length, result.Ciphertext.Length);
            Array.Copy(al, 0, macBytes, authenticatedData.Length + result.InitializationVector.Length + result.Ciphertext.Length, al.Length);
            byte[] macHash = _symmetricSignatureProvider.Sign(macBytes);
            result.AuthenticationTag = new byte[_authenticatedkeys.HmacKey.Key.Length];
            Array.Copy(macHash, result.AuthenticationTag, result.AuthenticationTag.Length);

            return result;
        }

        public virtual byte[] Decrypt(byte[] ciphertext, byte[] authenticatedData, byte[] iv, byte[] authenticationTag)
        {
            if (ciphertext == null || ciphertext.Length == 0)
                throw LogHelper.LogArgumentNullException(nameof(ciphertext));

            if (authenticatedData == null)
                throw LogHelper.LogArgumentNullException(nameof(authenticatedData));

            if (iv == null)
                throw LogHelper.LogArgumentNullException(nameof(iv));

            if (authenticationTag == null)
                throw LogHelper.LogArgumentNullException(nameof(authenticationTag));

            // Verify authentication Tag
            byte[] al = ConvertToBigEndian(authenticatedData.Length * 8);
            byte[] macBytes = new byte[authenticatedData.Length + iv.Length + ciphertext.Length + al.Length];
            Array.Copy(authenticatedData, 0, macBytes, 0, authenticatedData.Length);
            Array.Copy(iv, 0, macBytes, authenticatedData.Length, iv.Length);
            Array.Copy(ciphertext, 0, macBytes, authenticatedData.Length + iv.Length, ciphertext.Length);
            Array.Copy(al, 0, macBytes, authenticatedData.Length + iv.Length + ciphertext.Length, al.Length);
            if (!_symmetricSignatureProvider.Verify(macBytes, authenticationTag, _authenticatedkeys.HmacKey.Key.Length))
                throw LogHelper.LogExceptionMessage(new SecurityTokenDecryptionFailedException(string.Format(CultureInfo.InvariantCulture, LogMessages.IDX10650, Base64UrlEncoder.Encode(authenticatedData), Base64UrlEncoder.Encode(iv), Base64UrlEncoder.Encode(authenticationTag))));

            Aes aes = Aes.Create();
            aes.Mode = CipherMode.CBC;
            aes.Padding = PaddingMode.PKCS7;
            aes.Key = _authenticatedkeys.AesKey.Key;
            aes.IV = iv;

            byte[] plainText = null;
            try
            {
                plainText = Utility.Transform(aes.CreateDecryptor(), ciphertext, 0, ciphertext.Length);
            }
            catch (Exception ex)
            {
                throw LogHelper.LogExceptionMessage(new SecurityTokenDecryptionFailedException(string.Format(CultureInfo.InvariantCulture, LogMessages.IDX10654, ex)));
            }

            return plainText;
        }

        private AuthenticatedKeys GetAlgorithmParameters(SymmetricSecurityKey key, string algorithm)
        {

            int keyLength = 16;
            if (algorithm.Equals(SecurityAlgorithms.Aes128CbcHmacSha256, StringComparison.Ordinal))
            {
                if (key.Key.Length < 32)
                    throw LogHelper.LogExceptionMessage(new ArgumentOutOfRangeException(nameof(key), string.Format(CultureInfo.InvariantCulture, LogMessages.IDX10651, algorithm, 256)));
            }
            else if (algorithm.Equals(SecurityAlgorithms.Aes256CbcHmacSha512, StringComparison.Ordinal))
            {
                if (key.Key.Length < 64)
                    throw LogHelper.LogExceptionMessage(new ArgumentOutOfRangeException(nameof(key), string.Format(CultureInfo.InvariantCulture, LogMessages.IDX10651, algorithm, 512)));

                keyLength = 32;
            }
            else
            {
                throw LogHelper.LogExceptionMessage(new ArgumentOutOfRangeException(nameof(algorithm), string.Format(CultureInfo.InvariantCulture, LogMessages.IDX10652, algorithm)));
            }

            byte[] aesKey = new byte[keyLength];
            byte[] hmacKey = new byte[keyLength];
            Array.Copy(key.Key, 16, aesKey, 0, 16);
            Array.Copy(key.Key, hmacKey, 16);
            return new AuthenticatedKeys()
            {
                AesKey = new SymmetricSecurityKey(aesKey),
                HmacKey = new SymmetricSecurityKey(hmacKey)
            };
        }

        private string GetHashAlgorithm(string algorithm)
        {
            switch (algorithm)
            {
                case SecurityAlgorithms.Aes128CbcHmacSha256:
                    return SecurityAlgorithms.HmacSha256;

                case SecurityAlgorithms.Aes256CbcHmacSha512:
                    return SecurityAlgorithms.HmacSha512;

                default:
                    throw LogHelper.LogExceptionMessage(new ArgumentException(nameof(algorithm), String.Format(CultureInfo.InvariantCulture, LogMessages.IDX10652, algorithm)));
            }
        }

        private void ValidateKeySize(byte[] key, string algorithm)
        {
            switch (algorithm)
            {
                case SecurityAlgorithms.Aes128CbcHmacSha256:
                {
                    if (key.Length < 32)
                        throw LogHelper.LogExceptionMessage(new ArgumentOutOfRangeException("key.KeySize", string.Format(CultureInfo.InvariantCulture, LogMessages.IDX10653, SecurityAlgorithms.Aes128CbcHmacSha256, 256, key.Length << 3)));
                    break;
                }

                case SecurityAlgorithms.Aes256CbcHmacSha512:
                {
                    if (key.Length < 64)
                        throw LogHelper.LogExceptionMessage(new ArgumentOutOfRangeException("key.KeySize", string.Format(CultureInfo.InvariantCulture, LogMessages.IDX10653, SecurityAlgorithms.Aes256CbcHmacSha512, 512, key.Length << 3)));
                    break;
                }

                default:
                    throw LogHelper.LogExceptionMessage(new ArgumentException(nameof(algorithm), String.Format(CultureInfo.InvariantCulture, LogMessages.IDX10652, algorithm)));
            }
        }

        private static byte[] ConvertToBigEndian(long i)
        {
            byte[] temp = BitConverter.GetBytes(i);
            if (BitConverter.IsLittleEndian)
                Array.Reverse(temp);

            return temp;
        }
    }
}
