using System;

namespace Microsoft.IdentityModel.Tokens
{
    internal class AesGcm : IDisposable
    {
        public const int NonceSize = 12;
        public const int TagSize = 16;

        private static readonly SafeAlgorithmHandle s_aesGcm = AesBCryptModes.OpenAesAlgorithm(Cng.BCRYPT_CHAIN_MODE_GCM).Value;
        private SafeKeyHandle _keyHandle;
        public AesGcm(byte[] key)
        {
            if (key == null)
                throw new ArgumentNullException(nameof(key));

            ImportKey(key);
        }

        private void ImportKey(byte[] key)
        {
            _keyHandle = Interop.BCrypt.BCryptImportKey(s_aesGcm, key);
        }

        public void Dispose()
        {
            _keyHandle.Dispose();
        }

        public void Decrypt(byte[] nonce, byte[] ciphertext, byte[] tag, byte[] plaintext, byte[] associatedData = null)
        {
            AesAEAD.CheckArgumentsForNull(nonce, plaintext, ciphertext, tag);
            AesAEAD.Decrypt(_keyHandle, nonce, associatedData, ciphertext, tag, plaintext, clearPlaintextOnFailure: true);
        }
    }
}
