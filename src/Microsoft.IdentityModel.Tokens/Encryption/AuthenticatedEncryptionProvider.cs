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
        /// <exception cref="ArgumentException">a symmetricSignatureProvider is not created.</exception>
        /// </summary>
        public AuthenticatedEncryptionProvider(SecurityKey key, string algorithm)
        {
            if (key == null)
                throw LogHelper.LogArgumentNullException(nameof(key));

            if (string.IsNullOrWhiteSpace(algorithm))
                throw LogHelper.LogArgumentNullException(nameof(algorithm));

            if (!IsSupportedAlgorithm(key, algorithm))
                throw LogHelper.LogExceptionMessage(new ArgumentException(LogHelper.FormatInvariant(LogMessages.IDX10668, GetType(), algorithm, key)));

            ValidateKeySize(key, algorithm);
            _authenticatedkeys = GetAlgorithmParameters(key, algorithm);
            _hashAlgorithm = GetHashAlgorithm(algorithm);
            _symmetricSignatureProvider = key.CryptoProviderFactory.CreateForSigning(_authenticatedkeys.HmacKey, _hashAlgorithm) as SymmetricSignatureProvider;
            if (_symmetricSignatureProvider == null)
                throw LogHelper.LogExceptionMessage(new ArgumentException(LogHelper.FormatInvariant(LogMessages.IDX10649, Algorithm)));

            Key = key;
            Algorithm = algorithm;
        }

        /// <summary>
        /// Gets the encryption algorithm that is being used.
        /// </summary>
        public string Algorithm { get; private set; }

        /// <summary>
        /// Gets or sets a user context for a <see cref="AuthenticatedEncryptionProvider"/>.
        /// </summary>
        /// <remarks>This is null by default. This can be used by runtimes or for extensibility scenarios.</remarks>
        public string Context { get; set; }

        /// <summary>
        /// Gets the <see cref="SecurityKey"/> that is being used.
        /// </summary>
        public SecurityKey Key { get; private set; }

        /// <summary>
        /// Encrypts the 'plaintext'
        /// </summary>
        /// <param name="plaintext">the data to be encrypted.</param>
        /// <param name="authenticatedData">will be combined with iv and ciphertext to create an authenticationtag.</param>
        /// <returns><see cref="AuthenticatedEncryptionResult"/>containing ciphertext, iv, authenticationtag.</returns>
        /// <exception cref="ArgumentNullException">plaintext is null or empty.</exception>
        /// <exception cref="ArgumentNullException">authenticationData is null or empty.</exception>
        /// <exception cref="SecurityTokenEncryptionFailedException">AES crypto operation threw. See inner exception for details.</exception>
        public virtual AuthenticatedEncryptionResult Encrypt(byte[] plaintext, byte[] authenticatedData)
        {
            return Encrypt(plaintext, authenticatedData, null);
        }

        /// <summary>
        /// Encrypts the 'plaintext'
        /// </summary>
        /// <param name="plaintext">the data to be encrypted.</param>
        /// <param name="authenticatedData">will be combined with iv and ciphertext to create an authenticationtag.</param>
        /// <param name="iv">initialization vector for encryption.</param>
        /// <returns><see cref="AuthenticatedEncryptionResult"/>containing ciphertext, iv, authenticationtag.</returns>
        /// <exception cref="ArgumentNullException">plaintext is null or empty.</exception>
        /// <exception cref="ArgumentNullException">authenticationData is null or empty.</exception>
        /// <exception cref="SecurityTokenEncryptionFailedException">AES crypto operation threw. See inner exception for details.</exception>
        public virtual AuthenticatedEncryptionResult Encrypt(byte[] plaintext, byte[] authenticatedData, byte[] iv)
        {
            if (plaintext == null || plaintext.Length == 0)
                throw LogHelper.LogArgumentNullException(nameof(plaintext));

            if (authenticatedData == null || authenticatedData.Length == 0)
                throw LogHelper.LogArgumentNullException(nameof(authenticatedData));

            Aes aes = Aes.Create();
            aes.Mode = CipherMode.CBC;
            aes.Padding = PaddingMode.PKCS7;
            aes.Key = _authenticatedkeys.AesKey.Key;
            if (iv != null)
                aes.IV = iv;

            byte[] ciphertext;
            try
            {
                ciphertext = Utility.Transform(aes.CreateEncryptor(), plaintext, 0, plaintext.Length);
            }
            catch(Exception ex)
            {
                throw LogHelper.LogExceptionMessage(new SecurityTokenEncryptionFailedException(LogHelper.FormatInvariant(LogMessages.IDX10654, ex)));
            }

            byte[] al = Utility.ConvertToBigEndian(authenticatedData.Length * 8);
            byte[] macBytes = new byte[authenticatedData.Length + aes.IV.Length + ciphertext.Length + al.Length];
            Array.Copy(authenticatedData, 0, macBytes, 0, authenticatedData.Length);
            Array.Copy(aes.IV, 0, macBytes, authenticatedData.Length, aes.IV.Length);
            Array.Copy(ciphertext, 0, macBytes, authenticatedData.Length + aes.IV.Length, ciphertext.Length);
            Array.Copy(al, 0, macBytes, authenticatedData.Length + aes.IV.Length + ciphertext.Length, al.Length);
            byte[] macHash = _symmetricSignatureProvider.Sign(macBytes);
            var authenticationTag = new byte[_authenticatedkeys.HmacKey.Key.Length];
            Array.Copy(macHash, authenticationTag, authenticationTag.Length);

            return new AuthenticatedEncryptionResult(Key, ciphertext, aes.IV, authenticationTag);
        }

        /// <summary>
        /// Decrypts ciphertext into plaintext
        /// </summary>
        /// <param name="ciphertext">the encrypted text to decrypt.</param>
        /// <param name="authenticatedData">the authenticateData that is used in verification.</param>
        /// <param name="iv">the initialization vector used when creating the ciphertext.</param>
        /// <param name="authenticationTag">the authenticationTag that was created during the encyption.</param>
        /// <returns>decrypted ciphertext</returns>
        /// <exception cref="ArgumentNullException">'ciphertext' is null or empty.</exception>
        /// <exception cref="ArgumentNullException">'authenticatedData' is null or empty.</exception>
        /// <exception cref="ArgumentNullException">'iv' is null or empty.</exception>
        /// <exception cref="ArgumentNullException">'authenticationTag' is null or empty.</exception>
        /// <exception cref="SecurityTokenDecryptionFailedException">signature over authenticationTag fails to verify.</exception>
        /// <exception cref="SecurityTokenDecryptionFailedException">AES crypto operation threw. See inner exception.</exception>
        public virtual byte[] Decrypt(byte[] ciphertext, byte[] authenticatedData, byte[] iv, byte[] authenticationTag)
        {
            if (ciphertext == null || ciphertext.Length == 0)
                throw LogHelper.LogArgumentNullException(nameof(ciphertext));

            if (authenticatedData == null || authenticatedData.Length == 0)
                throw LogHelper.LogArgumentNullException(nameof(authenticatedData));

            if (iv == null || iv.Length == 0)
                throw LogHelper.LogArgumentNullException(nameof(iv));

            if (authenticationTag == null || authenticationTag.Length == 0)
                throw LogHelper.LogArgumentNullException(nameof(authenticationTag));

            // Verify authentication Tag
            byte[] al = Utility.ConvertToBigEndian(authenticatedData.Length * 8);
            byte[] macBytes = new byte[authenticatedData.Length + iv.Length + ciphertext.Length + al.Length];
            Array.Copy(authenticatedData, 0, macBytes, 0, authenticatedData.Length);
            Array.Copy(iv, 0, macBytes, authenticatedData.Length, iv.Length);
            Array.Copy(ciphertext, 0, macBytes, authenticatedData.Length + iv.Length, ciphertext.Length);
            Array.Copy(al, 0, macBytes, authenticatedData.Length + iv.Length + ciphertext.Length, al.Length);
            if (!_symmetricSignatureProvider.Verify(macBytes, authenticationTag, _authenticatedkeys.HmacKey.Key.Length))
                throw LogHelper.LogExceptionMessage(new SecurityTokenDecryptionFailedException(LogHelper.FormatInvariant(LogMessages.IDX10650, Base64UrlEncoder.Encode(authenticatedData), Base64UrlEncoder.Encode(iv), Base64UrlEncoder.Encode(authenticationTag))));

            Aes aes = Aes.Create();
            aes.Mode = CipherMode.CBC;
            aes.Padding = PaddingMode.PKCS7;
            aes.Key = _authenticatedkeys.AesKey.Key;
            aes.IV = iv;
            try
            {
                return Utility.Transform(aes.CreateDecryptor(), ciphertext, 0, ciphertext.Length);
            }
            catch (Exception ex)
            {
                throw LogHelper.LogExceptionMessage(new SecurityTokenDecryptionFailedException(LogHelper.FormatInvariant(LogMessages.IDX10654, ex)));
            }
        }

        /// <summary>
        /// Checks if an 'key, algorithm' pair is supported
        /// </summary>
        /// <param name="key">the <see cref="SecurityKey"/></param>
        /// <param name="algorithm">the algorithm to check.</param>
        /// <returns>true if 'key, algorithm' pair is supported.</returns>
        protected virtual bool IsSupportedAlgorithm(SecurityKey key, string algorithm)
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

            var jsonWebKey = key as JsonWebKey;
            if (jsonWebKey != null)
                return (jsonWebKey.K != null && jsonWebKey.Kty == JsonWebAlgorithmsKeyTypes.Octet);

            return false;
        }

        private AuthenticatedKeys GetAlgorithmParameters(SecurityKey key, string algorithm)
        {
            int keyLength = -1;
            if (algorithm.Equals(SecurityAlgorithms.Aes256CbcHmacSha512, StringComparison.Ordinal))
                keyLength = 32;
            else if (algorithm.Equals(SecurityAlgorithms.Aes192CbcHmacSha384, StringComparison.Ordinal))
                keyLength = 24;
            else if (algorithm.Equals(SecurityAlgorithms.Aes128CbcHmacSha256, StringComparison.Ordinal))
                keyLength = 16;
            else
                throw LogHelper.LogExceptionMessage(new ArgumentException(LogHelper.FormatInvariant(LogMessages.IDX10668, GetType(), algorithm, key)));

            var keyBytes = GetKeyBytes(key);
            byte[] aesKey = new byte[keyLength];
            byte[] hmacKey = new byte[keyLength];
            Array.Copy(keyBytes, keyLength, aesKey, 0, keyLength);
            Array.Copy(keyBytes, hmacKey, keyLength);
            return new AuthenticatedKeys()
            {
                AesKey = new SymmetricSecurityKey(aesKey),
                HmacKey = new SymmetricSecurityKey(hmacKey)
            };
        }

        private string GetHashAlgorithm(string algorithm)
        {
            if (SecurityAlgorithms.Aes128CbcHmacSha256.Equals(algorithm, StringComparison.Ordinal))
                    return SecurityAlgorithms.HmacSha256;

            if (SecurityAlgorithms.Aes192CbcHmacSha384.Equals(algorithm, StringComparison.Ordinal))
                return SecurityAlgorithms.HmacSha384;

            if (SecurityAlgorithms.Aes256CbcHmacSha512.Equals(algorithm, StringComparison.Ordinal))
                    return SecurityAlgorithms.HmacSha512;

            throw LogHelper.LogExceptionMessage(new ArgumentException(LogHelper.FormatInvariant(LogMessages.IDX10652, algorithm), nameof(algorithm)));
        }

        /// <summary>
        /// Called to obtain the byte[] needed to create a <see cref="KeyedHashAlgorithm"/>
        /// </summary>
        /// <param name="key"><see cref="SecurityKey"/>that will be used to obtain the byte[].</param>
        /// <returns><see cref="byte"/>[] that is used to populated the KeyedHashAlgorithm.</returns>
        /// <exception cref="ArgumentNullException">if key is null.</exception>
        /// <exception cref="ArgumentException">if a byte[] can not be obtained from SecurityKey.</exception>
        /// <remarks><see cref="SymmetricSecurityKey"/> and <see cref="JsonWebKey"/> are supported.
        /// <para>For a <see cref="SymmetricSecurityKey"/> .Key is returned</para>
        /// <para>For a <see cref="JsonWebKey"/>Base64UrlEncoder.DecodeBytes is called with <see cref="JsonWebKey.K"/> if <see cref="JsonWebKey.Kty"/> == JsonWebAlgorithmsKeyTypes.Octet</para>
        /// </remarks>
        protected virtual byte[] GetKeyBytes(SecurityKey key)
        {
            if (key == null)
                throw LogHelper.LogArgumentNullException(nameof(key));

            SymmetricSecurityKey symmetricSecurityKey = key as SymmetricSecurityKey;
            if (symmetricSecurityKey != null)
                return symmetricSecurityKey.Key;

            JsonWebKey jsonWebKey = key as JsonWebKey;
            if (jsonWebKey != null && jsonWebKey.K != null && jsonWebKey.Kty == JsonWebAlgorithmsKeyTypes.Octet)
                return Base64UrlEncoder.DecodeBytes(jsonWebKey.K);

            throw LogHelper.LogExceptionMessage(new ArgumentException(LogHelper.FormatInvariant(LogMessages.IDX10667, key)));
        }

        /// <summary>
        /// Checks that the key has sufficient length
        /// </summary>
        /// <param name="key"><see cref="SecurityKey"/> that contains bytes.</param>
        /// <param name="algorithm">the algorithm to apply.</param>
        /// <exception cref="ArgumentNullException">if 'key' is null.</exception>
        /// <exception cref="ArgumentNullException">if 'algorithm' is null or empty.</exception>
        protected virtual void ValidateKeySize(SecurityKey key, string algorithm)
        {
            if (key == null)
                throw LogHelper.LogArgumentNullException(nameof(key));

            if (string.IsNullOrEmpty(algorithm))
                throw LogHelper.LogArgumentNullException(nameof(algorithm));

            if (SecurityAlgorithms.Aes128CbcHmacSha256.Equals(algorithm, StringComparison.Ordinal))
            {
                if (key.KeySize < 256)
                    throw LogHelper.LogExceptionMessage(new ArgumentOutOfRangeException("key.KeySize", LogHelper.FormatInvariant(LogMessages.IDX10653, SecurityAlgorithms.Aes128CbcHmacSha256, 256, key.KeyId, key.KeySize)));

                return;
            }

            if (SecurityAlgorithms.Aes192CbcHmacSha384.Equals(algorithm, StringComparison.Ordinal))
            {
                if (key.KeySize < 384)
                    throw LogHelper.LogExceptionMessage(new ArgumentOutOfRangeException("key.KeySize", LogHelper.FormatInvariant(LogMessages.IDX10653, SecurityAlgorithms.Aes192CbcHmacSha384, 384, key.KeyId, key.KeySize)));

                return;
            }

            if (SecurityAlgorithms.Aes256CbcHmacSha512.Equals(algorithm, StringComparison.Ordinal))
            {
                if (key.KeySize < 512)
                    throw LogHelper.LogExceptionMessage(new ArgumentOutOfRangeException("key.KeySize", LogHelper.FormatInvariant(LogMessages.IDX10653, SecurityAlgorithms.Aes256CbcHmacSha512, 512, key.KeyId, key.KeySize)));

                return;
            }

            throw LogHelper.LogExceptionMessage(new ArgumentException(LogHelper.FormatInvariant(LogMessages.IDX10652, algorithm)));
        }
    }
}
