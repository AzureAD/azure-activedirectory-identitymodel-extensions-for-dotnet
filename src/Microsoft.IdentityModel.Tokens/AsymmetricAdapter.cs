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

#if NET45
using System.Reflection;
#endif

#if NET461 || NETSTANDARD2_0
using System.Security.Cryptography.X509Certificates;
#endif

namespace Microsoft.IdentityModel.Tokens
{
    delegate byte[] SignDelegate(byte[] bytes);
    delegate bool VerifyDelegate(byte[] bytes, byte[] signature);

    /// <summary>
    /// This adapter abstracts the 'RSA' differences between versions of .Net targets.
    /// </summary>
    internal class AsymmetricAdapter : IDisposable
    {
#if NET45
        // For users that have built targeting 4.5.1, 4.5.2 or 4.6.0 they will bind to our 4.5 target.
        // It is possible for the application to pass the call to X509Certificate2.GetRSAPublicKey() or X509Certificate2.GetRSAPrivateKey()
        // which returns RSACng(). Our 4.5 target doesn't know about this type and sees it as RSA, then things start to go bad.
        // We use reflection to detect that 4.6+ is available and access the appropriate signing or verifying methods.
        private static Type _hashAlgorithmNameType = typeof(object).Assembly.GetType("System.Security.Cryptography.HashAlgorithmName", false);
        private static Type _rsaSignaturePaddingType = typeof(object).Assembly.GetType("System.Security.Cryptography.RSASignaturePadding", false);
        private static volatile Func<RSA, byte[], string, byte[]> _rsaPkcs1SignMethod;
        private static volatile Func<RSA, byte[], byte[], string, bool> _rsaPkcs1VerifyMethod;
        private string _lightUpHashAlgorithmName = string.Empty;
        private const string _rsaCngTypeName = "System.Security.Cryptography.RSACng";
        private const string _dsaCngTypeName = "System.Security.Cryptography.DSACng";
#endif

#if DESKTOP
        private bool _useRSAOeapPadding = false;
#endif

#if NET461 || NETSTANDARD2_0
        private RSAEncryptionPadding _rsaEncryptionPadding;
#endif

        private bool _disposeCryptoOperators = false;
        private bool _disposed = false;
        private SignDelegate SignatureFunction;
        private VerifyDelegate VerifyFunction;

        private object _signRsaLock = new object();
        private object _signEcdsaLock = new object();
        private object _verifyRsaLock = new object();
        private object _verifyEcdsaLock = new object();

#if NET461 || NETSTANDARD2_0
        // HasAlgorithmName was introduced into Net46
        internal AsymmetricAdapter(SecurityKey key, string algorithm, HashAlgorithm hashAlgorithm, HashAlgorithmName hashAlgorithmName, bool requirePrivateKey)
            : this(key, algorithm, hashAlgorithm, requirePrivateKey)
        {
            HashAlgorithmName = hashAlgorithmName;
        }
#endif

        // Encryption algorithms do not need a HashAlgorithm, this is called by RSAKeyWrap
        internal AsymmetricAdapter(SecurityKey key, string algorithm, bool requirePrivateKey)
            : this(key, algorithm, null, requirePrivateKey)
        {
        }

        // This constructor will be used by NET45 for signing and for RSAKeyWrap
        internal AsymmetricAdapter(SecurityKey key, string algorithm, HashAlgorithm hashAlgorithm, bool requirePrivateKey)
        {
            HashAlgorithm = hashAlgorithm;

            // RsaSecurityKey has either Rsa OR RsaParameters.
            // If we use the RsaParameters, we create a new RSA object and will need to dispose.
            if (key is RsaSecurityKey rsaKey)
            {
                InitializeUsingRsaSecurityKey(rsaKey, algorithm);
            }
            else if (key is X509SecurityKey x509Key)
            {
                InitializeUsingX509SecurityKey(x509Key, algorithm, requirePrivateKey);
            }
            else if (key is JsonWebKey jsonWebKey)
            {
                if (JsonWebKeyConverter.TryConvertToSecurityKey(jsonWebKey, out SecurityKey securityKey))
                {
                    if (securityKey is RsaSecurityKey rsaSecurityKeyFromJsonWebKey)
                        InitializeUsingRsaSecurityKey(rsaSecurityKeyFromJsonWebKey, algorithm);
                    else if (securityKey is X509SecurityKey x509SecurityKeyFromJsonWebKey)
                        InitializeUsingX509SecurityKey(x509SecurityKeyFromJsonWebKey, algorithm, requirePrivateKey);
                    else if (securityKey is ECDsaSecurityKey edcsaSecurityKeyFromJsonWebKey)
                        InitializeUsingEcdsaSecurityKey(edcsaSecurityKeyFromJsonWebKey);
                    else
                        throw LogHelper.LogExceptionMessage(new NotSupportedException(LogHelper.FormatInvariant(LogMessages.IDX10684, algorithm, key)));
                }
            }
            else if (key is ECDsaSecurityKey ecdsaKey)
            {
                ECDsaSecurityKey = ecdsaKey;
                SignatureFunction = SignWithECDsa;
                VerifyFunction = VerifyWithECDsa;
            }
            else
                throw LogHelper.LogExceptionMessage(new NotSupportedException(LogHelper.FormatInvariant(LogMessages.IDX10684, algorithm, key)));
        }

        private void InitializeUsingRsaSecurityKey(RsaSecurityKey rsaSecurityKey, string algorithm)
        {
            if (rsaSecurityKey.Rsa != null)
            {
                InitializeUsingRsa(rsaSecurityKey.Rsa, algorithm);
            }
            else
            {
                var rsa = RSA.Create();
                rsa.ImportParameters(rsaSecurityKey.Parameters);
                InitializeUsingRsa(rsa, algorithm);
                _disposeCryptoOperators = true;
            }
        }

        private void InitializeUsingX509SecurityKey(X509SecurityKey x509SecurityKey, string algorithm, bool requirePrivateKey)
        {
            if (requirePrivateKey)
                InitializeUsingRsa(x509SecurityKey.PrivateKey as RSA, algorithm);
            else
                InitializeUsingRsa(x509SecurityKey.PublicKey as RSA, algorithm);
        }

        private void InitializeUsingEcdsaSecurityKey(ECDsaSecurityKey ecdsaSecurityKey)
        {
            ECDsaSecurityKey = ecdsaSecurityKey;
            SignatureFunction = SignWithECDsa;
            VerifyFunction = VerifyWithECDsa;
        }

        internal byte[] Decrypt(byte[] data)
        {
            // NET45 should have been passed RsaCryptoServiceProvider, DecryptValue may fail
            // We don't have 'lightup' for decryption / encryption.
#if NET45
            if (RsaCryptoServiceProviderProxy != null)
                return RsaCryptoServiceProviderProxy.Decrypt(data, _useRSAOeapPadding);
            else
                return RSA.DecryptValue(data);
#endif

            // NET461 could have been passed RSACryptoServiceProvider
#if NET461
            if (RsaCryptoServiceProviderProxy != null)
                return RsaCryptoServiceProviderProxy.Decrypt(data, _useRSAOeapPadding);
            else
                return RSA.Decrypt(data, _rsaEncryptionPadding);
#endif

            // NETSTANDARD2_0 doesn't use RSACryptoServiceProviderProxy
#if NETSTANDARD2_0
            return RSA.Decrypt(data, _rsaEncryptionPadding);
#endif
        }

        protected virtual void Dispose(bool disposing)
        {
            if (!_disposed)
            {
                _disposed = true;
                if (disposing)
                {
                    if (_disposeCryptoOperators)
                    {
                        if (ECDsaSecurityKey != null)
                            ECDsaSecurityKey.ECDsa.Dispose();
#if DESKTOP
                        if (RsaCryptoServiceProviderProxy != null)
                            RsaCryptoServiceProviderProxy.Dispose();
#endif
                        if (RSA != null)
                            RSA.Dispose();
                    }
                }
            }
        }

        /// <summary>
        /// Calls <see cref="Dispose(bool)"/> and <see cref="GC.SuppressFinalize"/>
        /// </summary>
        public void Dispose()
        {
            Dispose(true);
            GC.SuppressFinalize(this);
        }

        private ECDsaSecurityKey ECDsaSecurityKey { get; set; }

        internal byte[] Encrypt(byte[] data)
        {
            // NET45 should have been passed RsaCryptoServiceProvider, EncryptValue may fail
            // We don't have 'lightup' for decryption / encryption.
#if NET45
            if (RsaCryptoServiceProviderProxy != null)
                return RsaCryptoServiceProviderProxy.Encrypt(data, _useRSAOeapPadding);
            else
                return RSA.EncryptValue(data);
#endif

            // NET461 could have been passed RSACryptoServiceProvider
#if NET461
            if (RsaCryptoServiceProviderProxy != null)
                return RsaCryptoServiceProviderProxy.Encrypt(data, _useRSAOeapPadding);

            return RSA.Encrypt(data, _rsaEncryptionPadding);
#endif

            // NETSTANDARD2_0 doesn't use RSACryptoServiceProviderProxy
#if NETSTANDARD2_0
            return RSA.Encrypt(data, _rsaEncryptionPadding);
#endif
        }

        private HashAlgorithm HashAlgorithm { get; set; }

#if NET461 || NETSTANDARD2_0
        private HashAlgorithmName HashAlgorithmName { get; set; }

        private RSASignaturePadding RSASignaturePadding { get; set; }
#endif

        private void InitializeUsingRsa(RSA rsa, string algorithm)
        {

#if NET461 || NETSTANDARD2_0
            if (algorithm.Equals(SecurityAlgorithms.RsaSsaPssSha256, StringComparison.Ordinal) ||
                algorithm.Equals(SecurityAlgorithms.RsaSsaPssSha256Signature, StringComparison.Ordinal) ||
                algorithm.Equals(SecurityAlgorithms.RsaSsaPssSha384, StringComparison.Ordinal) ||
                algorithm.Equals(SecurityAlgorithms.RsaSsaPssSha384Signature, StringComparison.Ordinal) ||
                algorithm.Equals(SecurityAlgorithms.RsaSsaPssSha512, StringComparison.Ordinal) ||
                algorithm.Equals(SecurityAlgorithms.RsaSsaPssSha512Signature, StringComparison.Ordinal))
            {
                RSASignaturePadding = RSASignaturePadding.Pss;
            }
            else
            {
                // default RSASignaturePadding for other supported RSA algorithms is Pkcs1
                RSASignaturePadding = RSASignaturePadding.Pkcs1;
            }
#endif

            // This case is the result of a calling
            // X509Certificate2.GetPrivateKey OR X509Certificate2.GetPublicKey.Key
            // These calls return an AsymmetricAlgorithm which doesn't have API's to do much and need to be cast.
            // RSACryptoServiceProvider is wrapped to support SHA2
            // RSACryptoServiceProviderProxy is only supported on Windows platform
#if DESKTOP
            _useRSAOeapPadding = algorithm.Equals(SecurityAlgorithms.RsaOAEP, StringComparison.Ordinal)
                              || algorithm.Equals(SecurityAlgorithms.RsaOaepKeyWrap, StringComparison.Ordinal);

            if (rsa is RSACryptoServiceProvider rsaCryptoServiceProvider)
            {
                RsaCryptoServiceProviderProxy = new RSACryptoServiceProviderProxy(rsaCryptoServiceProvider);
                SignatureFunction = SignWithRsaCryptoServiceProviderProxy;
                VerifyFunction = VerifyWithRsaCryptoServiceProviderProxy;
                // RSACryptoServiceProviderProxy will keep track of if it creates a new RSA object.
                // Only if a new RSA was creaated, RSACryptoServiceProviderProxy will call RSA.Dispose().
                _disposeCryptoOperators = true;
                return;
            }
#endif

            // This case required the user to get a RSA object by calling
            // X509Certificate2.GetRSAPrivateKey() OR X509Certificate2.GetRSAPublicKey()
            // This requires 4.6+ to be installed. If a dependent library is targeting 4.5, 4.5.1, 4.5.2 or 4.6
            // they will use Net45, but the type is RSACng.
            // The 'lightup' code will bind to the correct operators.
#if NET45
            else if (rsa.GetType().ToString().Equals(_rsaCngTypeName, StringComparison.Ordinal) && IsRsaCngSupported())
            {
                _lightUpHashAlgorithmName = GetLightUpHashAlgorithmName();
                SignatureFunction = Pkcs1SignData;
                VerifyFunction = Pkcs1VerifyData;
                return;
            }
            else
            {
                // In NET45 we only support RSACryptoServiceProvider or "System.Security.Cryptography.RSACng"
                throw LogHelper.LogExceptionMessage(new NotSupportedException(LogHelper.FormatInvariant(LogMessages.IDX10687, typeof(RSACryptoServiceProvider).ToString(), _rsaCngTypeName, rsa.GetType().ToString())));
            }
#endif

#if NET461 || NETSTANDARD2_0
            // Here we can use RSA straight up.
            _rsaEncryptionPadding = (algorithm.Equals(SecurityAlgorithms.RsaOAEP, StringComparison.Ordinal) || algorithm.Equals(SecurityAlgorithms.RsaOaepKeyWrap, StringComparison.Ordinal))
                        ? RSAEncryptionPadding.OaepSHA1
                        : RSAEncryptionPadding.Pkcs1;
            RSA = rsa;
            SignatureFunction = SignWithRsa;
            VerifyFunction = VerifyWithRsa;
#endif
        }

        private RSA RSA { get; set; }

#if DESKTOP
        private RSACryptoServiceProviderProxy RsaCryptoServiceProviderProxy { get; set; }
#endif

        internal byte[] Sign(byte[] bytes)
        {
            if (SignatureFunction != null)
                return SignatureFunction(bytes);

            // we should never get here, its a bug if we do.
            throw LogHelper.LogExceptionMessage(new CryptographicException(LogMessages.IDX10685));
        }

        private byte[] SignWithECDsa(byte[] bytes)
        {
            lock (_signEcdsaLock)
            {
                return ECDsaSecurityKey.ECDsa.SignHash(HashAlgorithm.ComputeHash(bytes));
            }
        }

#if NET461 || NETSTANDARD2_0
        private byte[] SignWithRsa(byte[] bytes)
        {
            lock (_signRsaLock)
            {
                return RSA.SignHash(HashAlgorithm.ComputeHash(bytes), HashAlgorithmName, RSASignaturePadding);
            }
        }
#endif

#if DESKTOP
        internal byte[] SignWithRsaCryptoServiceProviderProxy(byte[] bytes)
        {
            return RsaCryptoServiceProviderProxy.SignData(bytes, HashAlgorithm);
        }
#endif

        internal bool Verify(byte[] bytes, byte[] signature)
        {
            if (VerifyFunction != null)
                return VerifyFunction(bytes, signature);

            // we should never get here, its a bug if we do.
            throw LogHelper.LogExceptionMessage(new NotSupportedException(LogMessages.IDX10686));
        }

        private bool VerifyWithECDsa(byte[] bytes, byte[] signature)
        {
            lock (_verifyEcdsaLock)
            {
                return ECDsaSecurityKey.ECDsa.VerifyHash(HashAlgorithm.ComputeHash(bytes), signature);
            }
        }

#if NET461 || NETSTANDARD2_0
        private bool VerifyWithRsa(byte[] bytes, byte[] signature)
        {
            lock (_verifyRsaLock)
            {
                return RSA.VerifyHash(HashAlgorithm.ComputeHash(bytes), signature, HashAlgorithmName, RSASignaturePadding);
            }
        }
#endif

#if DESKTOP
        private bool VerifyWithRsaCryptoServiceProviderProxy(byte[] bytes, byte[] signature)
        {
            lock (_verifyRsaLock)
            {
                return RsaCryptoServiceProviderProxy.VerifyData(bytes, HashAlgorithm, signature);
            }
        }
#endif

        // Put all the 'lightup' code here.
#if NET45
        private string GetLightUpHashAlgorithmName()
        {
            if (HashAlgorithm.HashSize == 256)
                return "SHA256";

            if (HashAlgorithm.HashSize == 384)
                return "SHA384";

            if (HashAlgorithm.HashSize == 512)
                return "SHA512";

            return HashAlgorithm.ToString();
        }

        /// <summary>
        /// The following code determines if RSACng is available on the .Net framework that is installed.
        /// </summary>
        private static Type GetSystemCoreType(string namespaceQualifiedTypeName)
        {
            Assembly systemCore = typeof(CngKey).Assembly;
            return systemCore.GetType(namespaceQualifiedTypeName, false);
        }

        private static bool IsRsaCngSupported()
        {
            Type rsaCng = GetSystemCoreType(_rsaCngTypeName);

            // If the type doesn't exist, there can't be good support for it.
            // (System.Core < 4.6)
            if (rsaCng == null)
                return false;

            Type dsaCng = GetSystemCoreType(_dsaCngTypeName);

            // The original implementation of RSACng returned shared objects in the CAPI fallback
            // pathway. That behavior is hard to test for, since CNG can load all CAPI software keys.
            // But, since DSACng was added in 4.6.2, and RSACng better guarantees uniqueness in 4.6.2
            // use that coincidence as a compatibility test.
            //
            // If DSACng is missing, RSACng usage might lead to attempting to use Disposed objects
            // (System.Core < 4.6.2)
            if (dsaCng == null)
                return false;

            // Create an RSACng instance and send it to RSAPKCS1KeyExchangeFormatter. It was adjusted to
            // be CNG-capable for 4.6.2; and other types in that library also are up-to-date.
            //
            // If mscorlib can't handle it properly, then other libraries probably can't, so we'll keep
            // preferring RSACryptoServiceProvider.
            try
            {
                new RSAPKCS1KeyExchangeFormatter((RSA)Activator.CreateInstance(rsaCng)).CreateKeyExchange(new byte[1]);
            }
            catch (Exception)
            {
                // (mscorlib < 4.6.2)
                return false;
            }

            return true;
        }

        private byte[] Pkcs1SignData(byte[] input)
        {
            if (_rsaPkcs1SignMethod == null)
            {
                // [X] SignData(byte[] data, HashAlgorithmName hashAlgorithmName, RSASignaturePadding padding)
                // [ ] SignData(byte[] data, int offset, int count, HashAlgorithmName hashAlgorithmName, RSASignaturePadding padding)
                // [ ] SignData(Stream data, HashAlgorithmName hashAlgorithmName, RSASignaturePadding padding)
                Type[] signatureTypes = { typeof(byte[]), _hashAlgorithmNameType, _rsaSignaturePaddingType };

                MethodInfo signDataMethod = typeof(RSA).GetMethod(
                    "SignData",
                    BindingFlags.Public | BindingFlags.Instance,
                    null,
                    signatureTypes,
                    null);

                var prop = _rsaSignaturePaddingType.GetProperty("Pkcs1", BindingFlags.Static | BindingFlags.Public);
                var properties = _rsaSignaturePaddingType.GetProperties(BindingFlags.Static | BindingFlags.Public);
                Type delegateType = typeof(Func<,,,,>).MakeGenericType(
                            typeof(RSA),
                            typeof(byte[]),
                            _hashAlgorithmNameType,
                            _rsaSignaturePaddingType,
                            typeof(byte[]));

                Delegate openDelegate = Delegate.CreateDelegate(delegateType, signDataMethod);
                _rsaPkcs1SignMethod = (rsaArg, dataArg, algorithmArg) =>
                {
                    object[] args =
                    {
                        rsaArg,
                        dataArg,
                        Activator.CreateInstance(_hashAlgorithmNameType, algorithmArg),
                        _rsaSignaturePaddingType.GetProperty("Pkcs1", BindingFlags.Static | BindingFlags.Public).GetValue(null)
                    };

                    return (byte[])openDelegate.DynamicInvoke(args);
                };
            }

            return _rsaPkcs1SignMethod(RSA, input, _lightUpHashAlgorithmName);
        }

        private bool Pkcs1VerifyData(byte[] input, byte[] signature)
        {
            if (_rsaPkcs1VerifyMethod == null)
            {
                // [X] VerifyData(byte[] data, byte[] signature, HashAlgorithmName hashAlgorithmName, RSASignaturePadding padding)
                // [ ] VerifyData(byte[] data, int offset, int count, byte[] signature, HashAlgorithmName hashAlgorithmName, RSASignaturePadding padding)
                // [ ] VerifyData(Stream data, byte[] signature, HashAlgorithmName hashAlgorithmName, RSASignaturePadding padding)
                Type[] signatureTypes = { typeof(byte[]), typeof(byte[]), _hashAlgorithmNameType, _rsaSignaturePaddingType };
                MethodInfo verifyDataMethod = typeof(RSA).GetMethod(
                    "VerifyData",
                    BindingFlags.Public | BindingFlags.Instance,
                    null,
                    signatureTypes,
                    null);

                Type delegateType = typeof(Func<,,,,,>).MakeGenericType(
                    typeof(RSA),
                    typeof(byte[]),
                    typeof(byte[]),
                    _hashAlgorithmNameType,
                    _rsaSignaturePaddingType,
                    typeof(bool));

                Delegate verifyDelegate = Delegate.CreateDelegate(delegateType, verifyDataMethod);
                _rsaPkcs1VerifyMethod = (rsaArg, dataArg, signatureArg, algorithmArg) =>
                {
                    object[] args =
                    {
                        rsaArg,
                        dataArg,
                        signatureArg,
                        Activator.CreateInstance(_hashAlgorithmNameType, algorithmArg),
                        _rsaSignaturePaddingType.GetProperty("Pkcs1", BindingFlags.Static | BindingFlags.Public).GetValue(null)
                    };

                    return (bool)verifyDelegate.DynamicInvoke(args);
                };
            }

            return _rsaPkcs1VerifyMethod(RSA, input, signature, _lightUpHashAlgorithmName);
        }
#endif
    }
}
