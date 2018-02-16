using System;
using System.Reflection;
using System.Security.Cryptography;
using System.Security.Cryptography.X509Certificates;
using LogHelper = Microsoft.IdentityModel.Logging.LogHelper;

namespace Microsoft.IdentityModel.Tokens
{
    internal class RunTimeMethodResolver
    {   
        // delegate definition
        public delegate RSA GetKeyDelegateRSA(X509Certificate2 certificate);

        public delegate AsymmetricAlgorithm GetKeyDelegateAsymmetricAlgorithm(X509Certificate2 certificate);

        // if the run time methods are resolved
        private static bool _resolved = false;

        // delegates related to RSA private key and public key
        private static GetKeyDelegateRSA _getPrivateKeyDelegateRSA = null;

        private static GetKeyDelegateRSA _getPublicKeyDelegateRSA = null;
      
        private static GetKeyDelegateAsymmetricAlgorithm _getPrivateKeyDelegateAsymmetricAlgorithm = null;

        private static GetKeyDelegateAsymmetricAlgorithm _getPublicKeyDelegateAsymmetricAlgorithm = null;

#if (NET45 || NET451)
        // RSA sign/verify data, encrypt/decrypt related objects in assembly

        private static object _RSASignaturePaddingPkcs1 = null;

        private static object _RSAEncryptionPaddingPkcs1 = null;

        private static object _RSAEncryptionPaddingOaepSHA1 = null;

        private static object _HashAlgorithmNameSHA256 = null;

        private static object _HashAlgorithmNameSHA384 = null;

        private static object _HashAlgorithmNameSHA512 = null;

        private static MethodInfo _rsaSignData = null;

        private static MethodInfo _rsaVerifyData = null;

        private static MethodInfo _rsaEncrypt = null;

        private static MethodInfo _rsaDecrypt = null;
#endif     

        public static byte[] SignData(RSA rsa, byte[] data, string algorithm)
        {
            ResolveRunTime();

            if (rsa == null)
                LogHelper.LogArgumentNullException(nameof(rsa));

            if (data == null)
                LogHelper.LogArgumentNullException(nameof(data));

            if (string.IsNullOrEmpty(algorithm))
                LogHelper.LogArgumentNullException(nameof(algorithm));

#if (NET45 || NET451)
            return _rsaSignData.Invoke(rsa, new object[] { data, GetHashAlgorithmName(algorithm), _RSASignaturePaddingPkcs1 }) as Byte[];
#else
            return rsa.SignData(data, GetHashAlgorithmname(algorithm), RSASignaturePadding.Pkcs1);
#endif
        }

        public static byte[] SignData(ECDsa ecdsa, byte[] data, string algorithm = null)
        {
            if (ecdsa == null)
                LogHelper.LogArgumentNullException(nameof(ecdsa));

            if (data == null)
                LogHelper.LogArgumentNullException(nameof(data));

#if (NET45 || NET451)
            return (ecdsa as ECDsaCng).SignData(data);
#else
            if (string.IsNullOrEmpty(algorithm))
                LogHelper.LogArgumentNullException(nameof(algorithm));

            return ecdsa.SignData(data, GetHashAlgorithmname(algorithm));
#endif
        }

        public static bool VerifyData(RSA rsa, byte[] data, byte[] signature, string algorithm)
        {
            ResolveRunTime();

            if (rsa == null)
                LogHelper.LogArgumentNullException(nameof(rsa));

            if (data == null)
                LogHelper.LogArgumentNullException(nameof(data));

            if (signature == null)
                LogHelper.LogArgumentNullException(nameof(signature));

            if (string.IsNullOrEmpty(algorithm))
                LogHelper.LogArgumentNullException(nameof(algorithm));

#if (NET45 || NET451)
            return (bool) _rsaVerifyData.Invoke(rsa, new object[] { data, signature, GetHashAlgorithmName(algorithm), _RSASignaturePaddingPkcs1 });
#else
            return rsa.VerifyData(data, signature, GetHashAlgorithmname(algorithm), RSASignaturePadding.Pkcs1);
#endif
        }

        public static bool VerifyData(ECDsa ecdsa, byte[] data, byte[] signature, string algorithm = null)
        {

            if (ecdsa == null)
                LogHelper.LogArgumentNullException(nameof(ecdsa));

            if (data == null)
                LogHelper.LogArgumentNullException(nameof(data));

            if (signature == null)
                LogHelper.LogArgumentNullException(nameof(signature));

#if (NET45 || NET451)
            return (ecdsa as ECDsaCng).VerifyData(data, signature);
#else
            if (string.IsNullOrEmpty(algorithm))
                LogHelper.LogArgumentNullException(nameof(algorithm));

            return ecdsa.VerifyData(data, signature, GetHashAlgorithmname(algorithm));
#endif
        }

        public static byte[] Decrypt(RSA rsa, byte[] data, bool fOAEP)
        {
            ResolveRunTime();

            if (rsa == null)
                LogHelper.LogArgumentNullException(nameof(rsa));

            if (data == null)
                LogHelper.LogArgumentNullException(nameof(data));

#if (NET45 || NET451)
            if (fOAEP)
                return _rsaDecrypt.Invoke(rsa, new object[] { data, _RSAEncryptionPaddingOaepSHA1 }) as Byte[];
            else
                return _rsaDecrypt.Invoke(rsa, new object[] { data, _RSAEncryptionPaddingPkcs1 }) as Byte[];
#else
            if (fOAEP)
                return rsa.Decrypt(data, RSAEncryptionPadding.OaepSHA1);
            else
                return rsa.Decrypt(data, RSAEncryptionPadding.Pkcs1);
#endif
        }

        public static byte[] Encrypt(RSA rsa, byte[] data, bool fOAEP)
        {
            ResolveRunTime();

            if (rsa == null)
                LogHelper.LogArgumentNullException(nameof(rsa));

            if (data == null)
                LogHelper.LogArgumentNullException(nameof(data));

#if (NET45 || NET451)
            if (fOAEP)
                return _rsaEncrypt.Invoke(rsa, new object[] { data, _RSAEncryptionPaddingOaepSHA1 }) as Byte[];
            else
                return _rsaEncrypt.Invoke(rsa, new object[] { data, _RSAEncryptionPaddingPkcs1 }) as Byte[];
#else
            if (fOAEP)
                return rsa.Encrypt(data, RSAEncryptionPadding.OaepSHA1);
            else
                return rsa.Encrypt(data, RSAEncryptionPadding.Pkcs1);
#endif
        }      

        public static void SetPrivateKey(X509Certificate2 certificate, RsaAlgorithm rsaAlgorithm)
        {
            ResolveRunTime();

            if (certificate == null)
                LogHelper.LogArgumentNullException(nameof(certificate));

            if (rsaAlgorithm == null)
                LogHelper.LogArgumentNullException(nameof(rsaAlgorithm));

#if (NET45 || NET451)            
            if (_getPrivateKeyDelegateRSA != null)
                rsaAlgorithm.rsa = _getPrivateKeyDelegateRSA(certificate);
            else
                rsaAlgorithm.rsaCryptoServiceProviderProxy = new RSACryptoServiceProviderProxy(_getPrivateKeyDelegateAsymmetricAlgorithm(certificate) as RSACryptoServiceProvider);
#else
            rsaAlgorithm.rsa = _getPrivateKeyDelegateRSA(certificate);
#endif
        }

        public static void SetPublicKey(X509Certificate2 certificate, RsaAlgorithm rsaAlgorithm)
        {
            ResolveRunTime();

            if (certificate == null)
                LogHelper.LogArgumentNullException(nameof(certificate));

            if (rsaAlgorithm == null)
                LogHelper.LogArgumentNullException(nameof(rsaAlgorithm));

#if (NET45 || NET451)
            if (_getPublicKeyDelegateRSA != null)
                rsaAlgorithm.rsa = _getPublicKeyDelegateRSA(certificate);
            else
                rsaAlgorithm.rsaCryptoServiceProviderProxy = new RSACryptoServiceProviderProxy(_getPublicKeyDelegateAsymmetricAlgorithm(certificate) as RSACryptoServiceProvider);
#else
            rsaAlgorithm.rsa = _getPublicKeyDelegateRSA(certificate);
#endif
        }

        public static AsymmetricAlgorithm GetPrivateKey(X509Certificate2 certificate)
        {
            ResolveRunTime();

            if (certificate == null)
                LogHelper.LogArgumentNullException(nameof(certificate));

            if (_getPrivateKeyDelegateRSA != null)
                return _getPrivateKeyDelegateRSA(certificate) as AsymmetricAlgorithm;
            else
                return _getPrivateKeyDelegateAsymmetricAlgorithm(certificate);
        }

        public static AsymmetricAlgorithm GetPublicKey(X509Certificate2 certificate)
        {
            ResolveRunTime();

            if (certificate == null)
                LogHelper.LogArgumentNullException(nameof(certificate));

            if (_getPublicKeyDelegateRSA != null)
                return _getPublicKeyDelegateRSA(certificate) as AsymmetricAlgorithm;
            else
                return _getPublicKeyDelegateAsymmetricAlgorithm(certificate);
        }

        private static void ResolveRunTime()
        {
            if (_resolved)
                return;

            _resolved = true;

#if (NET45 || NET451)
            Assembly systemCoreAssembly = null;
            Assembly mscorlibAssembly = null;

            foreach (var assem in AppDomain.CurrentDomain.GetAssemblies())
            {
                if (assem.GetName().Name == "System.Core")
                {
                    systemCoreAssembly = assem;
                }

                if (assem.GetName().Name == "mscorlib")
                {
                    mscorlibAssembly = assem;
                }

                if (systemCoreAssembly != null && mscorlibAssembly != null)
                    break;
            }

            // 1. GetRSAPrivateKey and GetRSAPublicKey

            if (systemCoreAssembly != null)
            {
                Type type = systemCoreAssembly.GetType("System.Security.Cryptography.X509Certificates.RSACertificateExtensions");
                if (type != null)
                {
                    var getPrivateKeyMethod = type.GetMethod("GetRSAPrivateKey");
                    if (getPrivateKeyMethod != null)
                    {
                        _getPrivateKeyDelegateRSA = certificate =>
                        {
                            object[] staticParameters = { certificate };
                            return getPrivateKeyMethod.Invoke(null, staticParameters) as RSA;
                        };
                    }

                    var getPublicKeyMethod = type.GetMethod("GetRSAPublicKey");
                    if (getPublicKeyMethod != null)
                    {
                        _getPublicKeyDelegateRSA = certificate =>
                        {
                            object[] staticParameters = { certificate };
                            return getPublicKeyMethod.Invoke(null, staticParameters) as RSA;
                        };
                    }
                }
            }

            if (_getPrivateKeyDelegateAsymmetricAlgorithm == null)
            {
                _getPrivateKeyDelegateAsymmetricAlgorithm = certificate =>
                {
                    return certificate.PrivateKey;
                };
            }

            if (_getPublicKeyDelegateAsymmetricAlgorithm == null)
            {
                _getPublicKeyDelegateAsymmetricAlgorithm = certificate =>
                {
                    return certificate.PublicKey.Key;
                };
            }

            // 2. Methods and properties in mscorlib

            if (mscorlibAssembly != null)
            {
                // 2.1 HashAlgorithmName
                var hashAlgorithmNameType = mscorlibAssembly.GetType("System.Security.Cryptography.HashAlgorithmName");

                if (hashAlgorithmNameType != null)
                {
                    // SHA256
                    var sha256Property = hashAlgorithmNameType.GetProperty("SHA256");
                    if (sha256Property != null)
                        _HashAlgorithmNameSHA256 = sha256Property.GetValue(null);

                    // SHA384
                    var sha384Property = hashAlgorithmNameType.GetProperty("SHA384");
                    if (sha384Property != null)
                        _HashAlgorithmNameSHA384 = sha384Property.GetValue(null);

                    // SHA512
                    var sha512Property = hashAlgorithmNameType.GetProperty("SHA512");
                    if (sha512Property != null)
                        _HashAlgorithmNameSHA512 = sha512Property.GetValue(null);
                }

                // 2.2 RSASignaturePadding
                var rsaSignaturePaddingType = mscorlibAssembly.GetType("System.Security.Cryptography.RSASignaturePadding");
                if (rsaSignaturePaddingType != null)
                {
                    // pkcs1
                    var pkcs1Property = rsaSignaturePaddingType.GetProperty("Pkcs1");
                    if (pkcs1Property != null)
                        _RSASignaturePaddingPkcs1 = pkcs1Property.GetValue(null);
                }

                // 2.3 RSASignaturePadding
                var rsaEncryptionPaddingType = mscorlibAssembly.GetType("System.Security.Cryptography.RSAEncryptionPadding");
                if (rsaEncryptionPaddingType != null)
                {
                    // pkcs1
                    var pkcs1Property = rsaEncryptionPaddingType.GetProperty("Pkcs1");
                    if (pkcs1Property != null)
                        _RSAEncryptionPaddingPkcs1 = pkcs1Property.GetValue(null);

                    // oaep
                    var oaepProperty = rsaEncryptionPaddingType.GetProperty("OaepSHA1");
                    if (oaepProperty != null)
                        _RSAEncryptionPaddingOaepSHA1 = oaepProperty.GetValue(null);
                }

                // 2.4 Methods in RSA class
                var rsaType = mscorlibAssembly.GetType("System.Security.Cryptography.RSA");
                if (rsaType != null)
                {
                    _rsaDecrypt = rsaType.GetMethod("Decrypt");
                    _rsaEncrypt = rsaType.GetMethod("Encrypt");
                    if (hashAlgorithmNameType != null && rsaSignaturePaddingType != null)
                    {
                        _rsaVerifyData = rsaType.GetMethod("VerifyData", new Type[] { typeof(Byte[]), typeof(Byte[]), hashAlgorithmNameType, rsaSignaturePaddingType });
                        _rsaSignData = rsaType.GetMethod("SignData", new Type[] { typeof(Byte[]), hashAlgorithmNameType, rsaSignaturePaddingType });
                    }
                }
            }

#else
            _getPrivateKeyDelegateRSA = certificate =>
            {
                return RSACertificateExtensions.GetRSAPrivateKey(certificate);
            };

            _getPublicKeyDelegateRSA = certificate =>
            {
                return RSACertificateExtensions.GetRSAPublicKey(certificate);
            };
#endif
        }

#if (NET45 || NET451)
        private static Object GetHashAlgorithmName(string algorithm)
        {
            switch (algorithm)
            {
                case SecurityAlgorithms.Sha256:
                    return _HashAlgorithmNameSHA256;
                case SecurityAlgorithms.Sha384:
                    return _HashAlgorithmNameSHA384;
                case SecurityAlgorithms.Sha512:
                    return _HashAlgorithmNameSHA512;
            }
            throw LogHelper.LogExceptionMessage(new RunTimeMethodResolverException(LogHelper.FormatInvariant(LogMessages.IDX10675, algorithm)));
        }
#else
        private static HashAlgorithmName GetHashAlgorithmname(string algorithm)
        {
            switch (algorithm)
            {
                case SecurityAlgorithms.Sha256:
                    return HashAlgorithmName.SHA256;
                case SecurityAlgorithms.Sha384:
                    return HashAlgorithmName.SHA384;
                case SecurityAlgorithms.Sha512:
                    return HashAlgorithmName.SHA512;
            }
            throw LogHelper.LogExceptionMessage(new RunTimeMethodResolverException(LogHelper.FormatInvariant(LogMessages.IDX10675, algorithm)));
        }
#endif
    }
}
