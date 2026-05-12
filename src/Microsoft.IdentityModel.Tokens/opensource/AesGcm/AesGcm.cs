// Copyright (c) Microsoft Corporation. All rights reserved.
// Licensed under the MIT License.

using System;

namespace Microsoft.IdentityModel.Tokens
{
    internal class AesGcm : IDisposable
    {
        public const int NonceSize = 12;
        public const int TagSize = 16;

#if NET6_0_OR_GREATER
        private System.Security.Cryptography.AesGcm _aesGcm;
#else
        private static readonly SafeAlgorithmHandle s_aesGcm = AesBCryptModes.OpenAesAlgorithm(Cng.BCRYPT_CHAIN_MODE_GCM).Value;
        private SafeKeyHandle _keyHandle;
#endif
        private bool _disposed;

        public AesGcm(byte[] key)
        {
            if (key == null)
                throw new ArgumentNullException(nameof(key));

            ImportKey(key);
        }

        private void ImportKey(byte[] key)
        {

#if NET8_0_OR_GREATER
            _aesGcm = new System.Security.Cryptography.AesGcm(key, TagSize);
#elif NET6_0_OR_GREATER
            // .NET 6 and .NET 7 use the obsolete constructor without tagSizeInBytes parameter
#pragma warning disable SYSLIB0053 // Type or member is obsolete
            _aesGcm = new System.Security.Cryptography.AesGcm(key);
#pragma warning restore SYSLIB0053 // Type or member is obsolete
#else
            _keyHandle = Interop.BCrypt.BCryptImportKey(s_aesGcm, key);
#endif
        }

        public void Dispose()
        {
            Dispose(true);
            GC.SuppressFinalize(this);
        }

        protected virtual void Dispose(bool disposing)
        {
            if (!_disposed && disposing)
            {
                _disposed = true;
#if NET6_0_OR_GREATER
                _aesGcm?.Dispose();
#else
                _keyHandle.Dispose();
#endif
            }
        }

        public void Decrypt(byte[] nonce, byte[] ciphertext, byte[] tag, byte[] plaintext, byte[] associatedData = null)
        {
            AesAead.CheckArgumentsForNull(nonce, plaintext, ciphertext, tag);
#if NET6_0_OR_GREATER
            try
            {
                _aesGcm.Decrypt(nonce, ciphertext, tag, plaintext, associatedData);
            }
            catch (Exception)
            {
                // prevent secrets from persisting in memory on decrypt failure
                CryptographicOperations.ZeroMemory(plaintext);
                throw;
            }
#else
            AesAead.Decrypt(_keyHandle, nonce, associatedData, ciphertext, tag, plaintext, clearPlaintextOnFailure: true);
#endif
        }

        #region FOR TESTING ONLY
        internal void Encrypt(byte[] nonce, byte[] plaintext, byte[] ciphertext, byte[] tag, byte[] associatedData = null)
        {
            AesAead.CheckArgumentsForNull(nonce, plaintext, ciphertext, tag);
#if NET6_0_OR_GREATER
            _aesGcm.Encrypt(nonce, plaintext, ciphertext, tag, associatedData);
#else
            AesAead.Encrypt(_keyHandle, nonce, associatedData, plaintext, ciphertext, tag);
#endif
        }
        #endregion
    }
}
