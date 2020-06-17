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

#if NET_CORE_3_0

using Microsoft.IdentityModel.Logging;
using System;
using System.Security.Cryptography;

namespace Microsoft.IdentityModel.Tokens.Saml.Tests
{
    // Helper AuthenticatedEncryptionProvider class made to mimic AES-GCM
    // remove when AES-GCM is released and supported
    public class AesGcmAuthenticatedEncryptionProvider : AuthenticatedEncryptionProvider
    {
        // http://www.w3.org/TR/xmlenc-core/#sec-AES-GCM
        private const int AES_GCM_IV_SIZE = 12;
        private const int AES_GCM_TAG_SIZE = 16;

        public AesGcmAuthenticatedEncryptionProvider(SecurityKey key, string algorithm) : base(key, algorithm)
        {
        }

        public override AuthenticatedEncryptionResult Encrypt(byte[] plaintext, byte[] authenticatedData)
        {
            return Encrypt(plaintext, authenticatedData, null);
        }

        public override AuthenticatedEncryptionResult Encrypt(byte[] plaintext, byte[] authenticatedData, byte[] iv)
        {
            if (IsAesGcmAlgorithm(Algorithm))
            {

                byte[] ciphertext = new byte[plaintext.Length];
                byte[] nonce = new byte[AES_GCM_IV_SIZE];
                byte[] tag = new byte[AES_GCM_TAG_SIZE];

                using (var aesGcm = new AesGcm(GetKeyBytes(Key)))
                {
                    //random nonce
                    RandomNumberGenerator rng = RandomNumberGenerator.Create();
                    rng.GetBytes(nonce);

                    try
                    {
                        aesGcm.Encrypt(nonce, plaintext, ciphertext, tag);
                    }
                    catch (Exception ex)
                    {
                        throw LogHelper.LogExceptionMessage(new SecurityTokenEncryptionFailedException(LogHelper.FormatInvariant("Tokens.LogMessages.IDX10618", Algorithm), ex));
                    }
                }

                return new AuthenticatedEncryptionResult(Key, ciphertext, nonce, tag);
            }

            return null;
        }

        public override byte[] Decrypt(byte[] ciphertext, byte[] authenticatedData, byte[] iv, byte[] authenticationTag)
        {
            if (IsAesGcmAlgorithm(Algorithm))
            {

                int cipherSize = ciphertext.Length - AES_GCM_IV_SIZE - AES_GCM_TAG_SIZE;

                if (cipherSize < 1)
                    throw LogHelper.LogExceptionMessage(new SecurityTokenDecryptionFailedException(LogHelper.FormatInvariant("Tokens.LogMessages.IDX10620")));

                byte[] cipher = new byte[cipherSize];
                byte[] nonce = new byte[AES_GCM_IV_SIZE];
                byte[] tag = new byte[AES_GCM_TAG_SIZE];

                Array.Copy(ciphertext, 0, nonce, 0, AES_GCM_IV_SIZE);
                Array.Copy(ciphertext, AES_GCM_IV_SIZE, cipher, 0, cipherSize);
                Array.Copy(ciphertext, ciphertext.Length - AES_GCM_TAG_SIZE, tag, 0, AES_GCM_TAG_SIZE);

                byte[] plaintext = new byte[cipher.Length];

                using (var aesGcm = new AesGcm(GetKeyBytes(Key)))
                {
                    try
                    {
                        aesGcm.Decrypt(nonce, cipher, tag, plaintext);
                        return plaintext;
                    }
                    catch (Exception ex)
                    {
                        throw LogHelper.LogExceptionMessage(new SecurityTokenDecryptionFailedException(LogHelper.FormatInvariant("Tokens.LogMessages.IDX10619", Algorithm), ex));
                    }
                }
            }

            return null;
        }

        protected override bool IsSupportedAlgorithm(SecurityKey key, string algorithm)
        {
            return IsAesGcmAlgorithm(algorithm);
        }

        private bool IsAesGcmAlgorithm(string algorithm)
        {
            if (!(algorithm.Equals(SecurityAlgorithms.Aes128Gcm, StringComparison.Ordinal)
              || algorithm.Equals(SecurityAlgorithms.Aes192Gcm, StringComparison.Ordinal)
              || algorithm.Equals(SecurityAlgorithms.Aes256Gcm, StringComparison.Ordinal)))
                return false;

            return true;
        }
    }

    //dummy implementation until AesGcm is released
    class AesGcm : IDisposable
    {
        public AesGcm(byte[] key)
        {
        }

        public void Dispose()
        {
            // throw new NotImplementedException();
        }

        public void Encrypt(byte[] nonce, byte[] plaintext, byte[] ciphertext, byte[] tag, byte[] associatedData = null)
        {
            Array.Copy(plaintext, ciphertext, plaintext.Length);
            RandomNumberGenerator rng = RandomNumberGenerator.Create();
            rng.GetBytes(tag);
        }

        public void Decrypt(byte[] nonce, byte[] ciphertext, byte[] tag, byte[] plaintext, byte[] associatedData = null)
        {
            Array.Copy(ciphertext, plaintext, ciphertext.Length);
        }
    }
}

#endif
