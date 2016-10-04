using System;
using System.Collections.Generic;
//using System.Runtime.InteropServices;
using System.Security.Cryptography;
using Microsoft.IdentityModel.Logging;

namespace Microsoft.IdentityModel.Tokens
{
    public class RsaProvider : EncryptionProvider
    {
        private SecurityKey _key;

#if NETSTANDARD1_4
        private bool _disposeRsa;
        private RSA _rsa;
        private RSAEncryptionPadding _padding;
#else
        private RSACryptoServiceProvider _rsaCryptoServiceProvider;
        private bool _fOAEP;
#endif
        private RSACryptoServiceProviderProxy _rsaCryptoServiceProviderProxy;
        private bool _disposed;

        public static readonly int DefaultMinimumKeySize = 2048;

        public RsaProvider(SecurityKey key, string alg)
        {
            if (key == null)
                throw LogHelper.LogArgumentNullException("key");

            if (alg == null)
                throw LogHelper.LogArgumentNullException("alg");

#if NETSTANDARD1_4
            _padding = ResolvePaddingMode(alg);
#else
            switch (alg)
            {
                case SecurityAlgorithms.RsaPKCS1:
                    _fOAEP = false;
                    break;

                case SecurityAlgorithms.RsaOAEP:
                    _fOAEP = true;
                    break;

                default:
                    // TODO(Yan): Add exception
                    throw LogHelper.LogArgumentException<ArgumentException>(nameof(alg), String.Format("Unsupported algorithm: {0}", alg));
            }
#endif

            ValidateKeySize(key, alg);
            _key = key;
        }
        
        public override EncryptionResult Encrypt(byte[] plaintext)
        {
            if(plaintext == null)
                throw LogHelper.LogArgumentNullException("plaintext");

            if (plaintext.Length == 0)
                throw LogHelper.LogException<ArgumentException>("Cannot encrypt empty 'plaintext'");

            EncryptionResult result = new EncryptionResult();

            // Resolve public key
#if NETSTANDARD1_4
            ResolveAlgorithm(_key, false);
            if (_rsa != null)
            {
                result.CipherText = _rsa.Encrypt(plaintext, _padding);
                return result;
            }
#else
            ResolveAlgorithm(_key, false);
            if (_rsaCryptoServiceProvider != null)
            {
                result.CipherText = _rsaCryptoServiceProvider.Encrypt(plaintext, _fOAEP);
                return result;
            }
#endif
                // TODO (Yan) : Add exception and throw
                throw LogHelper.LogException<InvalidOperationException>("Cannot get valid rsa");
        }

        public override byte[] Decrypt(byte[] ciphertext)
        {
            if (ciphertext == null)
                throw LogHelper.LogArgumentNullException("ciphertext");

            if (ciphertext.Length == 0)
                throw LogHelper.LogException<ArgumentException>("Cannot encrypt empty 'ciphertext'");

            if (!HasPrivateKey(_key))
                throw LogHelper.LogException<InvalidOperationException>(LogMessages.IDX10638, _key);

#if NETSTANDARD1_4
            // Resolve private key
            ResolveAlgorithm(_key, true);
            if (_rsa != null)
                return _rsa.Decrypt(ciphertext, _padding);
#else
            ResolveAlgorithm(_key, true);
            if (_rsaCryptoServiceProvider != null)
                return _rsaCryptoServiceProvider.Decrypt(ciphertext, _fOAEP);
#endif
                // TODO (Yan) Add a new log message for this 
                throw LogHelper.LogException<InvalidOperationException>(LogMessages.IDX10644);
        }

#if NETSTANDARD1_4
        private void ResolveAlgorithm(SecurityKey key, bool isPrivateKey)
        {
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
                    _disposeRsa = true;
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
                    _disposeRsa = true;
                    return;
                }
            }

            throw LogHelper.LogArgumentException<ArgumentOutOfRangeException>(nameof(key), LogMessages.IDX10641, key);
        }
#else
        private void ResolveAlgorithm(SecurityKey key, bool isPrivateKey)
        {
            if (key == null)
                throw LogHelper.LogArgumentNullException("key");
            
            RsaSecurityKey rsaKey = key as RsaSecurityKey;

            if (rsaKey != null)
            {
                if (rsaKey.Rsa != null)
                    _rsaCryptoServiceProvider = rsaKey.Rsa as RSACryptoServiceProvider;

                if (_rsaCryptoServiceProvider == null)
                {
                    _rsaCryptoServiceProvider = new RSACryptoServiceProvider();
                    (_rsaCryptoServiceProvider as RSA).ImportParameters(rsaKey.Parameters);
                }
                return;
            }

            X509SecurityKey x509Key = key as X509SecurityKey;
            if (x509Key != null)
            {
                if (isPrivateKey)
                    _rsaCryptoServiceProviderProxy = new RSACryptoServiceProviderProxy(x509Key.PrivateKey as RSACryptoServiceProvider);
                else
                    _rsaCryptoServiceProviderProxy = new RSACryptoServiceProviderProxy(x509Key.PublicKey as RSACryptoServiceProvider);
                return;
            }

            JsonWebKey webKey = key as JsonWebKey;
            if (webKey.Kty == JsonWebAlgorithmsKeyTypes.RSA)
            {
                RSAParameters parameters = CreateRsaParametersFromJsonWebKey(webKey, isPrivateKey);
                _rsaCryptoServiceProvider = new RSACryptoServiceProvider();
                (_rsaCryptoServiceProvider as RSA).ImportParameters(parameters);
                return;
            }

            throw LogHelper.LogArgumentException<ArgumentOutOfRangeException>(nameof(key), LogMessages.IDX10641, key);
        }
#endif
        private bool HasPrivateKey(SecurityKey key)
        {
            AsymmetricSecurityKey asymmetricSecurityKey = key as AsymmetricSecurityKey;
            if (asymmetricSecurityKey != null)
                return asymmetricSecurityKey.HasPrivateKey;

            JsonWebKey jsonWebKey = key as JsonWebKey;
            if (jsonWebKey != null)
                return jsonWebKey.HasPrivateKey;

            return false;
        }

#if NETSTANDARD1_4
        private RSAEncryptionPadding ResolvePaddingMode(string algorithm)
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
#endif

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

        private void ValidateKeySize(SecurityKey key, string algorithm)
        {
            if (key == null)
                throw LogHelper.LogArgumentNullException("key");

            if (key.KeySize < RsaProvider.DefaultMinimumKeySize)
                // TODO (Yan) : Add excepiton and throw
                throw LogHelper.LogArgumentException<ArgumentOutOfRangeException>("Key.KeySize", String.Format("The '{0}' for signing cannot be smaller than '{1}' bits. KeySize: '{2}'.", key, algorithm, key.KeySize));
        }

        protected override void Dispose(bool disposing)
        {
            if (!_disposed)
            {
                _disposed = true;

                if (disposing)
                {
#if NETSTANDARD1_4
                    if (_rsa != null && _disposeRsa)
                        _rsa.Dispose();
#else
                    if (_rsaCryptoServiceProvider != null)
                        _rsaCryptoServiceProvider.Dispose();
#endif

                    if (_rsaCryptoServiceProviderProxy != null)
                        _rsaCryptoServiceProviderProxy.Dispose();
                }
            }
        }
    }
}
