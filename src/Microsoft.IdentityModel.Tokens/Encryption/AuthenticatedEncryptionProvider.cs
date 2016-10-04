using System;
using System.Collections.Generic;
using System.Linq;
using System.Security.Cryptography;
using Microsoft.IdentityModel.Logging;
using System.Text;

namespace Microsoft.IdentityModel.Tokens
{
    public class AuthenticatedEncryptionProvider
    {
        // Used for encrypting.
        private Aes _aes;
        private SymmetricSignatureProvider _symmetricSignatureProvider;
    //    private byte[] _authenticationTag;
        private bool generateKey = false;

        // Used for decrypting.
 //      private AuthenticatedEncryptionParameters _authenticatedEncryptionParameters;

        // For encryption
        public AuthenticatedEncryptionProvider(SecurityKey key, string algorithm)
        {
            if (algorithm == null)
                throw LogHelper.LogArgumentNullException("algorithm");

            if (algorithm.Length == 0)
                throw LogHelper.LogException<ArgumentException>("Cannot encrypt empty 'algorithm'");

            _aes = Aes.Create();
            _aes.Mode = CipherMode.CBC;
            _aes.Padding = PaddingMode.PKCS7;

            string hashAlgorithm = GetHashAlgorithm(algorithm);

            if (key == null)
            {
                // Need generate when encrypting every time.
                generateKey = true;

                int keySize = GetKeySize(algorithm);
                _aes.KeySize = keySize;
                // Use aes key as hmac key
                _symmetricSignatureProvider = new SymmetricSignatureProvider(new SymmetricSecurityKey(_aes.Key), hashAlgorithm);
            }
            else
            {
                byte[] cek = null;
                SymmetricSecurityKey symmetricSecurityKey = key as SymmetricSecurityKey;
                if (symmetricSecurityKey != null)
                    cek = symmetricSecurityKey.Key;
                else
                {
                    JsonWebKey jsonWebKey = key as JsonWebKey;
                    if (jsonWebKey != null && jsonWebKey.K != null)
                        cek = Base64UrlEncoder.DecodeBytes(jsonWebKey.K);
                }

                if (cek == null)
                    // TODO (Yan) : Add log messages for this
                    throw LogHelper.LogArgumentException<ArgumentException>(nameof(key), LogMessages.IDX10703);

                ValidateKeySize(cek, algorithm);

                byte[] aesKey;
                byte[] hmacKey;
                GetAlgorithmParameters(algorithm, cek, out aesKey, out hmacKey);
                _aes.Key = aesKey;
                _symmetricSignatureProvider = new SymmetricSignatureProvider(new SymmetricSecurityKey(hmacKey), hashAlgorithm);
            }
        }

        // With this signature we don't need any out params,
        // Caller has to generate iv.
        public virtual EncryptionResult Encrypt(byte[] plaintext, byte[] authenticatedData)
        {
            if (plaintext == null)
                throw LogHelper.LogArgumentNullException("plaintext");

            if (plaintext.Length == 0)
                throw LogHelper.LogException<ArgumentException>("Cannot encrypt empty 'plaintext'");

            if (generateKey)
            {
                // Generate aes key every time.
                _aes.GenerateKey();
                _symmetricSignatureProvider.updateKey(new SymmetricSecurityKey(_aes.Key));
            }

            // Generate IV every time.
            _aes.GenerateIV();

            var result = new EncryptionResult();

            // result.CipherText = _aes.CreateEncryptor().TransformFinalBlock(plaintext, 0, plaintext.Length);
            result.CipherText = EncryptionUtilities.Transform(_aes.CreateEncryptor(), plaintext, 0, plaintext.Length);
            result.Key = new byte[(_aes.KeySize >> 3) + (_symmetricSignatureProvider.Key.KeySize >> 3)];
            SymmetricSecurityKey hmacKey = _symmetricSignatureProvider.Key as SymmetricSecurityKey;
            if (hmacKey == null)
                throw LogHelper.LogException<ArgumentException>("HMAC key is not symmetric key.");

            Array.Copy(hmacKey.Key, 0, result.Key, 0, hmacKey.Key.Length);
            Array.Copy(_aes.Key, 0, result.Key, hmacKey.Key.Length, _aes.Key.Length);

            result.InitialVector = _aes.IV;

            byte[] al = ConvertToBigEndian(authenticatedData.Length * 8);
            byte[] macBytes = new byte[authenticatedData.Length + result.InitialVector.Length + result.CipherText.Length + al.Length];
            Array.Copy(authenticatedData, 0, macBytes, 0, authenticatedData.Length);
            Array.Copy(result.InitialVector, 0, macBytes, authenticatedData.Length, result.InitialVector.Length);
            Array.Copy(result.CipherText, 0, macBytes, authenticatedData.Length + result.InitialVector.Length, result.CipherText.Length);
            Array.Copy(al, 0, macBytes, authenticatedData.Length + result.InitialVector.Length + result.CipherText.Length, al.Length);
            byte[] macHash = _symmetricSignatureProvider.Sign(macBytes);
            result.AuthenticationTag = new byte[hmacKey.Key.Length];
            Array.Copy(macHash, result.AuthenticationTag, result.AuthenticationTag.Length);

            return result;
        }

        public virtual byte[] Decrypt(byte[] ciphertext, byte[] authenticatedData, byte[] iv, byte[] authenticationTag)
        {
            if (ciphertext == null)
                throw LogHelper.LogArgumentNullException("ciphertext");

            if (ciphertext.Length == 0)
                throw LogHelper.LogException<ArgumentException>("Cannot encrypt empty 'ciphertext'");

            if (authenticatedData == null)
                // TODO (Yan) : Add exception log message and throw;
                throw LogHelper.LogArgumentNullException("authenticatedData");

            if (iv == null)
                throw LogHelper.LogArgumentNullException("iv");

            if (authenticationTag == null)
                throw LogHelper.LogArgumentNullException("authenticationTag");

            SymmetricSecurityKey hmacKey = _symmetricSignatureProvider.Key as SymmetricSecurityKey;
            if (hmacKey == null)
                throw LogHelper.LogException<ArgumentException>("HMAC key is not symmetric key.");

            // Verify authentication Tag
            byte[] al = ConvertToBigEndian(authenticatedData.Length * 8);
            byte[] macBytes = new byte[authenticatedData.Length + iv.Length + ciphertext.Length + al.Length];
            Array.Copy(authenticatedData, 0, macBytes, 0, authenticatedData.Length);
            Array.Copy(iv, 0, macBytes, authenticatedData.Length, iv.Length);
            Array.Copy(ciphertext, 0, macBytes, authenticatedData.Length + iv.Length, ciphertext.Length);
            Array.Copy(al, 0, macBytes, authenticatedData.Length + iv.Length + ciphertext.Length, al.Length);
            if (!_symmetricSignatureProvider.Verify(macBytes, authenticationTag, hmacKey.Key.Length))
                throw LogHelper.LogException<ArgumentException>(string.Format("Failed to verify ciphertext with aad: '{0}'; iv: '{1}'; and authenticationTag: '{2}'.", Base64UrlEncoder.Encode(authenticatedData), Base64UrlEncoder.Encode(iv), Base64UrlEncoder.Encode(authenticationTag)));

            _aes.IV = iv;
            return EncryptionUtilities.Transform(_aes.CreateDecryptor(), ciphertext, 0, ciphertext.Length);
        }

        private void GetAlgorithmParameters(string algorithm, byte[] key, out byte[] aes_key, out byte[] hmac_key)
        {
            switch (algorithm)
            {
                case Aes128CbcHmacSha256.AlgorithmName:
                    {
                        if ((key.Length << 3) < 256)
                            // TODO (Yan) : Add log message
                            throw LogHelper.LogArgumentException<ArgumentOutOfRangeException>("key", LogMessages.IDX10628, 256);

                        hmac_key = new byte[128 >> 3];
                        aes_key = new byte[128 >> 3];
                        Array.Copy(key, hmac_key, 128 >> 3);
                        Array.Copy(key, 128 >> 3, aes_key, 0, 128 >> 3);
                        break;
                    }

                case Aes256CbcHmacSha512.AlgorithmName:
                    {
                        if ((key.Length << 3) < 512)
                            throw LogHelper.LogArgumentException<ArgumentOutOfRangeException>("key", LogMessages.IDX10628, 512);

                        hmac_key = new byte[256 >> 3];
                        aes_key = new byte[256 >> 3];
                        Array.Copy(key, hmac_key, 256 >> 3);
                        Array.Copy(key, 256 >> 3, aes_key, 0, 256 >> 3);
                        break;
                    }

                default:
                    {
                        throw LogHelper.LogArgumentException<ArgumentOutOfRangeException>("algorithm", nameof(algorithm));
                    }
            }
        }

        private int GetKeySize(string algorithm)
        {
            switch (algorithm)
            {
                case SecurityAlgorithms.Aes128CbcHmacSha256:
                    return 256;

                case SecurityAlgorithms.Aes256CbcHmacSha512:
                    return 512;

                default:
                    //TODO (Yan) : Add new exception to logMessages and throw;
                    throw LogHelper.LogArgumentException<ArgumentException>(nameof(algorithm), String.Format("Unsupported algorithm: {0}", algorithm));
            }
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
                    //TODO (Yan) : Add new exception to logMessages and throw;
                    throw LogHelper.LogArgumentException<ArgumentException>(nameof(algorithm), String.Format("Unsupported algorithm: {0}", algorithm));
            }
        }

        private void ValidateKeySize(byte[] key, string algorithm)
        {
            switch (algorithm)
            {
                case SecurityAlgorithms.Aes128CbcHmacSha256:
                    {
                        if ((key.Length << 3) < 256)
                            // TODO (Yan) : Add new exception to LogMessages and throw;
                            throw LogHelper.LogArgumentException<ArgumentOutOfRangeException>("key.KeySize", LogMessages.IDX10630, key, algorithm, key.Length << 3);
                        break;
                    }

                case SecurityAlgorithms.Aes256CbcHmacSha512:
                    {
                        if ((key.Length << 3) < 512)
                            // TODO (Yan) : Add new exception to LogMessages and throw;
                            throw LogHelper.LogArgumentException<ArgumentOutOfRangeException>("key.KeySize", LogMessages.IDX10630, key, algorithm, key.Length << 3);
                        break;
                    }

                default:
                    //TODO (Yan) : Add new exception to logMessages and throw;
                    throw LogHelper.LogArgumentException<ArgumentException>(nameof(algorithm), String.Format("Unsupported algorithm: {0}", algorithm));
            }
        }

        private static byte[] ConvertToBigEndian(Int64 i)
        {
            byte[] temp = BitConverter.GetBytes(i);

            if (BitConverter.IsLittleEndian)
            {
                Array.Reverse(temp);
            }

            return temp;
        }

        public void Dispose()
        {
            Dispose(true);
            GC.SuppressFinalize(this);
        }

        protected virtual void Dispose(bool disposing)
        {
            if (disposing)
            {
            }
        }
    }
}
