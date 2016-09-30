using System;
using System.Collections.Generic;
using System.Linq;
using System.Security.Cryptography;
using Microsoft.IdentityModel.Logging;
using System.Text;

namespace Microsoft.IdentityModel.Tokens
{
    public class AuthenticatedEncryptionProvider : EncryptionProvider
    {
        // Used for encrypting.
        private byte[] _cek;
        private Aes _aes;
        private SymmetricSignatureProvider _symmetricSignatureProvider;
        private byte[] _authenticatedData;
        private byte[] _authenticationTag;

        // Used for decrypting.
        private AuthenticatedEncryptionParameters _authenticatedEncryptionParameters;

        // For encryption
        public AuthenticatedEncryptionProvider(SecurityKey key, string algorithm, byte[] authenticationData)
            :this(key, algorithm, authenticationData, null)
        {
        }

        // For decryption
        public AuthenticatedEncryptionProvider(string algorithm, byte[] authenticationData, AuthenticatedEncryptionParameters authenticatedEncryptionParameters)
            :this(null, algorithm, authenticationData, authenticatedEncryptionParameters)
        {
        }

        // key used for encrypt, authenticatedEncryptionParameters be used for decrypt.
        // public AuthenticatedEncryptionProvider(SecurityKey key, string algorithm, byte[] authenticationData, AuthenticatedEncryptionParameters authenticatedEncryptionParameters)
        private AuthenticatedEncryptionProvider(SecurityKey key, string algorithm, byte[] authenticationData, AuthenticatedEncryptionParameters authenticatedEncryptionParameters)
        {
            if (algorithm == null)
                throw LogHelper.LogArgumentNullException("algorithm");

            if (algorithm.Length == 0)
                throw LogHelper.LogException<ArgumentException>("Cannot encrypt empty 'algorithm'");

            if (authenticationData == null || authenticationData.Length == 0)
            // TODO (Yan) : Add exception log message and throw;
                throw LogHelper.LogArgumentException<ArgumentException>(nameof(authenticationData), "Encoded Protect Header could not be null or empty.");
            
            string hashAlgorithm = GetHashAlgorithm(algorithm);

            byte[] aesKey;
            byte[] hmacKey;
            _aes = Aes.Create();
            _aes.Mode = CipherMode.CBC;
            _aes.Padding = PaddingMode.PKCS7;

            if (authenticatedEncryptionParameters != null)
            {
                // For Decrypting
                ValidateKeySize(authenticatedEncryptionParameters.CEK, algorithm);
                _authenticatedEncryptionParameters = authenticatedEncryptionParameters;
                GetAlgorithmParameters(algorithm, authenticatedEncryptionParameters.CEK, out aesKey, out hmacKey);
                _aes.Key = aesKey;
                _aes.IV = authenticatedEncryptionParameters.InitialVector;
                _authenticationTag = authenticatedEncryptionParameters.AuthenticationTag;
                _symmetricSignatureProvider = new SymmetricSignatureProvider(new SymmetricSecurityKey(hmacKey), GetHashAlgorithm(algorithm));
            }
            else
            {
                // For Encrypting
                if (key != null)
                {
                    // try to use the provided key directly.
                    SymmetricSecurityKey symmetricSecurityKey = key as SymmetricSecurityKey;
                    if (symmetricSecurityKey != null)
                        _cek = symmetricSecurityKey.Key;
                    else
                    {
                        JsonWebKey jsonWebKey = key as JsonWebKey;
                        if (jsonWebKey != null && jsonWebKey.K != null)
                            _cek = Base64UrlEncoder.DecodeBytes(jsonWebKey.K);
                    }

                    if (_cek == null)
                        // TODO (Yan) : Add log messages for this
                        throw LogHelper.LogArgumentException<ArgumentException>(nameof(key), LogMessages.IDX10703);

                    ValidateKeySize(_cek, algorithm);

                    GetAlgorithmParameters(algorithm, _cek, out aesKey, out hmacKey);
                    _aes.Key = aesKey;
                    _symmetricSignatureProvider = new SymmetricSignatureProvider(new SymmetricSecurityKey(hmacKey), GetHashAlgorithm(algorithm));
                }
                else
                {
                    int keySize = GetKeySize(algorithm);
                    _aes.KeySize = keySize;
                    // Use aes key as hmac key
                    _symmetricSignatureProvider = new SymmetricSignatureProvider(new SymmetricSecurityKey(_aes.Key), GetHashAlgorithm(algorithm));
                }
            }

            _authenticatedData = authenticationData;
        }

        // With this signature we don't need any out params,
        // Caller has to generate iv.
        public override EncryptionResult Encrypt(byte[] plaintext)
        {
            if (plaintext == null)
                throw LogHelper.LogArgumentNullException("plaintext");

            if (plaintext.Length == 0)
                throw LogHelper.LogException<ArgumentException>("Cannot encrypt empty 'plaintext'");

            var result = new EncryptionResult();

            result.CipherText = _aes.CreateEncryptor().TransformFinalBlock(plaintext, 0, plaintext.Length);
            result.Key = new byte[_aes.KeySize >> 3 + _symmetricSignatureProvider.Key.KeySize >> 3];
            SymmetricSecurityKey hmacKey = _symmetricSignatureProvider.Key as SymmetricSecurityKey;
            if (hmacKey == null)
                throw LogHelper.LogException<ArgumentException>("HMAC key is not symmetric key.");

            Array.Copy(hmacKey.Key, 0, result.Key, 0, hmacKey.Key.Length);
            Array.Copy(_aes.Key, 0, result.Key, hmacKey.Key.Length, _aes.Key.Length);

            result.InitialVector = _aes.IV;

            byte[] al = ConvertToBigEndian(_authenticatedData.Length * 8);
            byte[] macBytes = new byte[_authenticatedData.Length + result.InitialVector.Length + result.CipherText.Length + al.Length];
            Array.Copy(_authenticatedData, 0, macBytes, 0, _authenticatedData.Length);
            Array.Copy(result.InitialVector, 0, macBytes, _authenticatedData.Length, result.InitialVector.Length);
            Array.Copy(result.CipherText, 0, macBytes, _authenticatedData.Length + result.InitialVector.Length, result.CipherText.Length);
            Array.Copy(al, 0, macBytes, _authenticatedData.Length + result.InitialVector.Length + result.CipherText.Length, al.Length);
            byte[] macHash = _symmetricSignatureProvider.Sign(macBytes);
            result.AuthenticationTag = new byte[hmacKey.Key.Length];
            Array.Copy(macHash, result.AuthenticationTag, result.AuthenticationTag.Length);

            return result;
        }

        public override byte[] Decrypt(byte[] ciphertext)
        {
            if (ciphertext == null)
                throw LogHelper.LogArgumentNullException("ciphertext");

            if (ciphertext.Length == 0)
                throw LogHelper.LogException<ArgumentException>("Cannot encrypt empty 'ciphertext'");

            if (_authenticatedData == null)
                // TODO (Yan) : Add exception log message and throw;
                throw LogHelper.LogArgumentNullException("_authenticatedData");

            //IAuthenticatedCryptoTransform authenticatedCryptoTransform = (IAuthenticatedCryptoTransform)_algorithm.CreateDecryptor(_authenticatedEncryptionParameters.CEK,
            //    _authenticatedEncryptionParameters.InitialVector, _authenticatedData);
            //  byte[] result = authenticatedCryptoTransform.TransformFinalBlock(ciphertext, 0, ciphertext.Length);

            SymmetricSecurityKey hmacKey = _symmetricSignatureProvider.Key as SymmetricSecurityKey;
            if (hmacKey == null)
                throw LogHelper.LogException<ArgumentException>("HMAC key is not symmetric key.");

            // Verify authentication Tag
            byte[] al = ConvertToBigEndian(_authenticatedData.Length * 8);
            byte[] macBytes = new byte[_authenticatedData.Length + _aes.IV.Length + ciphertext.Length + al.Length];
            Array.Copy(_authenticatedData, 0, macBytes, 0, _authenticatedData.Length);
            Array.Copy(_aes.IV, 0, macBytes, _authenticatedData.Length, _aes.IV.Length);
            Array.Copy(ciphertext, 0, macBytes, _authenticatedData.Length + _aes.IV.Length, ciphertext.Length);
            Array.Copy(al, 0, macBytes, _authenticatedData.Length + _aes.IV.Length + ciphertext.Length, al.Length);
            if (!_symmetricSignatureProvider.Verify(macBytes, _authenticationTag, hmacKey.Key.Length))
                throw LogHelper.LogException<ArgumentException>(string.Format("Failed to decrypt {0} with enc key {1}, hmac key {2}", ciphertext, _aes.Key, hmacKey.Key));

            try
            {
                return _aes.CreateDecryptor().TransformFinalBlock(ciphertext, 0, ciphertext.Length);
            }
            catch (Exception ex)
            {
                throw ex;
            }
        }

        //private AesCbcHmacSha2 ResolveAlgorithm(string algorithm)
        //{
        //    switch(algorithm)
        //    {
        //        case SecurityAlgorithms.Aes128CbcHmacSha256:
        //            return new Aes128CbcHmacSha256();

        //        case SecurityAlgorithms.Aes256CbcHmacSha512:
        //            return new Aes256CbcHmacSha512();

        //        default:
        //            //TODO (Yan) : Add new exception to logMessages and throw;
        //            throw LogHelper.LogArgumentException<ArgumentException>(nameof(algorithm), LogMessages.IDX10703);
        //    }
        //}

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
