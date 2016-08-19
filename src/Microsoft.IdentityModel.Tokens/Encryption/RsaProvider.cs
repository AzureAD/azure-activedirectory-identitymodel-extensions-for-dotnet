using System;
using System.Collections.Generic;
//using System.Runtime.InteropServices;
using System.Security.Cryptography;
using Microsoft.IdentityModel.Logging;

namespace Microsoft.IdentityModel.Tokens
{
    public class RsaProvider : IDecryptionProvider, IEncryptionProvider
    {
        private RSA _rsa;
        private byte[] _cek;
        private SecurityKey _encryptedKey;
      //  private RSACryptoServiceProviderProxy _rsaCryptoServiceProviderProxy;
        private RSAEncryptionPadding _padding;

        public RsaProvider(SecurityKey key, string alg)
        {
            if (key == null)
            {
                _cek = GenerateCEK();
               // _encryptedKey = ??? how to convert cek to SecurityKey
            }

            _encryptedKey = key;

            _padding = ResolveAlgorithm(alg);
        }

        public byte[] Encrypt(byte[] plaintext, out object extraOutputs)
        {
            if(plaintext == null)
                throw LogHelper.LogArgumentNullException("plaintext");

            // Resolve public key
            ResolveKey(_encryptedKey, false);

            // TODO :  1. generate iv if required for the algorithm, not for this case(rsa);

            // TODO : generate AuthenticateTag
            if (_cek !=null)
                byte[] authenticationTag = GenerateAuthenticateTag(_cek, , 0)

            object outputs = new AuthenticatedEncryptionParameters()
            {
                Key = _cek,
                InitialVector = new byte[0],
                AuthenticationTag = 
            }

            if (_rsa != null)
                return _rsa.Encrypt(plaintext, _padding);

        }

        public byte[] Decrypt(byte[] ciphertext)
        {
            if (ciphertext == null)
                throw LogHelper.LogArgumentNullException("ciphertext");

            if (!HasPrivateKey(_key))
                throw LogHelper.LogException<InvalidOperationException>(LogMessages.IDX10638, _key);

            // Resolve private key
            ResolveKey(_key, true);

            if (_rsa != null)
                return _rsa.Decrypt(ciphertext, _padding);

            // TODO (Yan) Add a new log message for this 
            throw LogHelper.LogException<InvalidOperationException>(LogMessages.IDX10644);
        }

        private void ResolveKey(SecurityKey key, bool isPrivateKey)
        {
            if (_rsa != null)
                return;

            if (key == null)
                throw LogHelper.LogArgumentNullException("key");

            RsaSecurityKey rsaKey = key as RsaSecurityKey;
            if (rsaKey != null)
            {
                if (rsaKey.Rsa != null)
                {
                    _rsa = rsaKey.Rsa;
                    return;
                }

                _rsa = RSA.Create();
                if (_rsa != null)
                {
                    _rsa.ImportParameters(rsaKey.Parameters);
                    // _disposeRsa = true;
                    return;
                }
            }

            X509SecurityKey x509Key = key as X509SecurityKey;
            if (x509Key != null)
            {
                if (isPrivateKey)
                {
                    RSACryptoServiceProvider rsaCsp = x509Key.PrivateKey as RSACryptoServiceProvider;
                    if (rsaCsp != null)
                        _rsaCryptoServiceProviderProxy = new RSACryptoServiceProviderProxy(rsaCsp);
                    else
                        _rsa = x509Key.PrivateKey as RSA;
                }
                else
                    _rsa = x509Key.PublicKey as RSA;

                return;
            }

            JsonWebKey webKey = key as JsonWebKey;
            if (webKey.Kty == JsonWebAlgorithmsKeyTypes.RSA)
            {
                RSAParameters parameters = CreateRsaParametersFromJsonWebKey(webKey, isPrivateKey);

                _rsa = RSA.Create();
                if (_rsa != null)
                {
                    _rsa.ImportParameters(parameters);
                    //  _disposeRsa = true;
                    return;
                }
            }

            throw LogHelper.LogArgumentException<ArgumentOutOfRangeException>(nameof(key), LogMessages.IDX10641, key);
        }

        private byte[] GenerateCEK()
        {
            byte[] cek = null;
            return cek;

        }

        private byte[] GenerateAuthenticateTag(byte[] inputKey, int macKeySize, int encKeySize)
        {
            byte[] authenticateTag = null;
            return authenticateTag;
        }

        private void GetKeySize(string algorithm, out int macKeySize, out int encKeySize)
        {
            macKeySize = 0;
            encKeySize = 0;
        }
        
        private bool HasPrivateKey(SecurityKey key)
        {
            return false;
        }


        private void ValidateSecurityKeySize()
        { }

        private RSAEncryptionPadding ResolveAlgorithm(string algorithm)
        {
            switch (algorithm)
            {
                case SecurityAlgorithms.RsaPKCS1:
                    return RSAEncryptionPadding.Pkcs1;

                case SecurityAlgorithms.RsaOAEP:
                    return RSAEncryptionPadding.OaepSHA1;

                // TODO : add case RSAEncryptionPadding.OaepSHA256:

                default:
                    throw LogHelper.LogArgumentException<ArgumentException>(nameof(algorithm), LogMessages.IDX10640, algorithm);
            }
        }

        private RSAParameters CreateRsaParametersFromJsonWebKey(JsonWebKey webKey, bool isPrivateKey)
        {
            if (webKey == null)
                throw LogHelper.LogArgumentNullException(nameof(webKey));

            if (webKey.N == null || webKey.E == null)
                throw LogHelper.LogException<ArgumentException>(LogMessages.IDX10700, webKey);

            RSAParameters parameters;
            if (isPrivateKey)
            {
                if (webKey.D == null || webKey.DP == null || webKey.DQ == null || webKey.QI == null || webKey.P == null || webKey.Q == null)
                    throw LogHelper.LogArgumentException<ArgumentNullException>(nameof(webKey), LogMessages.IDX10702, webKey);

                parameters = new RSAParameters()
                {
                    D = Base64UrlEncoder.DecodeBytes(webKey.D),
                    DP = Base64UrlEncoder.DecodeBytes(webKey.DP),
                    DQ = Base64UrlEncoder.DecodeBytes(webKey.DQ),
                    Exponent = Base64UrlEncoder.DecodeBytes(webKey.E),
                    Modulus = Base64UrlEncoder.DecodeBytes(webKey.N),
                    InverseQ = Base64UrlEncoder.DecodeBytes(webKey.QI),
                    P = Base64UrlEncoder.DecodeBytes(webKey.P),
                    Q = Base64UrlEncoder.DecodeBytes(webKey.Q)
                };
            }
            else
            {
                parameters = new RSAParameters()
                {
                    Exponent = Base64UrlEncoder.DecodeBytes(webKey.E),
                    Modulus = Base64UrlEncoder.DecodeBytes(webKey.N),
                };
            }
            return parameters;
        }
    }
}
