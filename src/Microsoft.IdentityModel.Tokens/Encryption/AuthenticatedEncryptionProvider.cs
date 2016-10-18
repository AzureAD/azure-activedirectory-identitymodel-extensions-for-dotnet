using System;
using System.Collections.Generic;
using System.Globalization;
using System.Linq;
using System.Security.Cryptography;
using Microsoft.IdentityModel.Logging;
using System.Text;

namespace Microsoft.IdentityModel.Tokens
{
    public class AuthenticatedEncryptionProvider
    {
        private struct AuthenticatedKeys
        {
            public byte[] aesKey;
            public byte[] hmacKey;
        }

        private SymmetricSecurityKey _key;
        private string _algorithm;

        public AuthenticatedEncryptionProvider(SecurityKey key, string algorithm)
        {
            if (key == null)
                throw LogHelper.LogArgumentNullException(nameof(key));

            if (string.IsNullOrWhiteSpace(algorithm))
                throw LogHelper.LogArgumentNullException(nameof(algorithm));

            _key = key as SymmetricSecurityKey;
            if (_key == null)
                throw LogHelper.LogExceptionMessage(new ArgumentException(LogMessages.IDX10648, nameof(key)));

            ValidateKeySize(_key.Key, algorithm);
            _algorithm = algorithm;
        }

        public virtual EncryptionResult Encrypt(byte[] plaintext, byte[] authenticatedData)
        {
            if (plaintext == null || plaintext.Length == 0)
                throw LogHelper.LogArgumentNullException(nameof(plaintext));

            if (authenticatedData == null)
                throw LogHelper.LogArgumentNullException(nameof(authenticatedData));

            AuthenticatedKeys keys = GetAlgorithmParameters(_algorithm, _key.Key);

            Aes aes = Aes.Create();
            aes.Mode = CipherMode.CBC;
            aes.Padding = PaddingMode.PKCS7;
            aes.Key = keys.aesKey;
            SignatureProvider symmetricSignatureProvider = _key.CryptoProviderFactory.CreateForSigning(new SymmetricSecurityKey(keys.hmacKey), GetHashAlgorithm(_algorithm));

            var result = new EncryptionResult();
            result.CipherText = Utility.Transform(aes.CreateEncryptor(), plaintext, 0, plaintext.Length);
            result.Key = _key.Key;
            result.InitializationVector = aes.IV;

            byte[] al = ConvertToBigEndian(authenticatedData.Length * 8);
            byte[] macBytes = new byte[authenticatedData.Length + result.InitializationVector.Length + result.CipherText.Length + al.Length];
            Array.Copy(authenticatedData, 0, macBytes, 0, authenticatedData.Length);
            Array.Copy(result.InitializationVector, 0, macBytes, authenticatedData.Length, result.InitializationVector.Length);
            Array.Copy(result.CipherText, 0, macBytes, authenticatedData.Length + result.InitializationVector.Length, result.CipherText.Length);
            Array.Copy(al, 0, macBytes, authenticatedData.Length + result.InitializationVector.Length + result.CipherText.Length, al.Length);
            byte[] macHash = symmetricSignatureProvider.Sign(macBytes);
            result.AuthenticationTag = new byte[keys.hmacKey.Length];
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

            AuthenticatedKeys keys = GetAlgorithmParameters(_algorithm, _key.Key);
            SymmetricSignatureProvider symmetricSignatureProvider = _key.CryptoProviderFactory.CreateForVerifying(new SymmetricSecurityKey(keys.hmacKey), GetHashAlgorithm(_algorithm)) as SymmetricSignatureProvider;
            if (symmetricSignatureProvider == null)
                throw LogHelper.LogExceptionMessage(new InvalidOperationException(string.Format(CultureInfo.InvariantCulture, LogMessages.IDX10649, _algorithm)));

            // Verify authentication Tag
            byte[] al = ConvertToBigEndian(authenticatedData.Length * 8);
            byte[] macBytes = new byte[authenticatedData.Length + iv.Length + ciphertext.Length + al.Length];
            Array.Copy(authenticatedData, 0, macBytes, 0, authenticatedData.Length);
            Array.Copy(iv, 0, macBytes, authenticatedData.Length, iv.Length);
            Array.Copy(ciphertext, 0, macBytes, authenticatedData.Length + iv.Length, ciphertext.Length);
            Array.Copy(al, 0, macBytes, authenticatedData.Length + iv.Length + ciphertext.Length, al.Length);
            if (!symmetricSignatureProvider.Verify(macBytes, authenticationTag, keys.hmacKey.Length))
                throw LogHelper.LogExceptionMessage(new ArgumentException(string.Format(CultureInfo.InvariantCulture, LogMessages.IDX10650, Base64UrlEncoder.Encode(authenticatedData), Base64UrlEncoder.Encode(iv), Base64UrlEncoder.Encode(authenticationTag))));

            Aes aes = Aes.Create();
            aes.Mode = CipherMode.CBC;
            aes.Padding = PaddingMode.PKCS7;
            aes.Key = keys.aesKey;
            aes.IV = iv;
            return Utility.Transform(aes.CreateDecryptor(), ciphertext, 0, ciphertext.Length);
        }

        private AuthenticatedKeys GetAlgorithmParameters(string algorithm, byte[] key)
        {
            switch (algorithm)
            {
                case SecurityAlgorithms.Aes128CbcHmacSha256:
                    {
                        if (key.Length < 32)
                            throw LogHelper.LogExceptionMessage(new ArgumentOutOfRangeException(nameof(key), string.Format(CultureInfo.InvariantCulture, LogMessages.IDX10651, algorithm, 256)));

                        AuthenticatedKeys keys = new AuthenticatedKeys();
                        keys.hmacKey = new byte[16];
                        keys.aesKey = new byte[16];
                        Array.Copy(key, keys.hmacKey, 16);
                        Array.Copy(key, 16, keys.aesKey, 0, 16);
                        return keys;
                    }

                case SecurityAlgorithms.Aes256CbcHmacSha512:
                    {
                        if (key.Length < 64)
                            throw LogHelper.LogExceptionMessage(new ArgumentOutOfRangeException(nameof(key), string.Format(CultureInfo.InvariantCulture, LogMessages.IDX10651, algorithm, 512)));

                        AuthenticatedKeys keys = new AuthenticatedKeys();
                        keys.hmacKey = new byte[32];
                        keys.aesKey = new byte[32];
                        Array.Copy(key, keys.hmacKey, 32);
                        Array.Copy(key, 32, keys.aesKey, 0, 32);
                        return keys;
                    }

                default:
                    {
                        throw LogHelper.LogExceptionMessage(new ArgumentOutOfRangeException(nameof(algorithm), string.Format(CultureInfo.InvariantCulture, LogMessages.IDX10652, algorithm)));
                    }
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
                            throw LogHelper.LogExceptionMessage(new ArgumentOutOfRangeException("key.KeySize", string.Format(CultureInfo.InvariantCulture, LogMessages.IDX10653, 32, key.Length << 3)));
                        break;
                    }

                case SecurityAlgorithms.Aes256CbcHmacSha512:
                    {
                        if (key.Length < 64)
                            throw LogHelper.LogExceptionMessage(new ArgumentOutOfRangeException("key.KeySize", string.Format(CultureInfo.InvariantCulture, LogMessages.IDX10653, 64, key.Length << 3)));
                        break;
                    }

                default:
                    throw LogHelper.LogExceptionMessage(new ArgumentException(nameof(algorithm), String.Format(CultureInfo.InvariantCulture, LogMessages.IDX10652, algorithm)));
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
    }
}
