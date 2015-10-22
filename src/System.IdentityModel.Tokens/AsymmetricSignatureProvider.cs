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

using System.Collections.Generic;
using System.Collections.ObjectModel;
using System.Diagnostics.Tracing;
using System.Globalization;
using System.Security.Cryptography;
using System.Security.Cryptography.X509Certificates;
using Microsoft.IdentityModel.Logging;

namespace System.IdentityModel.Tokens
{
    /// <summary>
    /// Provides signing and verifying operations when working with an <see cref="AsymmetricSecurityKey"/>
    /// </summary>
    public class AsymmetricSignatureProvider : SignatureProvider
    {
        private bool disposed;
#if DNXCORE50
        private RSA _rsa;
        private HashAlgorithmName _hashAlgorithm;
        private ECDsa _ecdsaCng;
#else
        private RSACryptoServiceProvider _rsaCryptoServiceProvider;
        private string _hashAlgorithm;
        private ECDsaCng _ecdsaCng;
#endif
        private RSACryptoServiceProviderProxy _rsaCryptoServiceProviderProxy;
        private IReadOnlyDictionary<string, int> _minimumAsymmetricKeySizeInBitsForSigningMap;
        private IReadOnlyDictionary<string, int> _minimumAsymmetricKeySizeInBitsForVerifyingMap;

        /// <summary>
        /// Mapping from algorithm to minimum <see cref="AsymmetricSecurityKey"/>.KeySize when creating signatures.
        /// </summary>
        public static readonly Dictionary<string, int> DefaultMinimumAsymmetricKeySizeInBitsForSigningMap = new Dictionary<string, int>()
        {
            { SecurityAlgorithms.ECDSA_SHA256, 256 },
            { SecurityAlgorithms.ECDSA_SHA384, 256 },
            { SecurityAlgorithms.ECDSA_SHA512, 256 },
            { SecurityAlgorithms.RSA_SHA256, 2048 },
            { SecurityAlgorithms.RSA_SHA384, 2048 },
            { SecurityAlgorithms.RSA_SHA512, 2048 },
            { SecurityAlgorithms.RsaSha256Signature, 2048 },
            { SecurityAlgorithms.RsaSha384Signature, 2048 },
            { SecurityAlgorithms.RsaSha512Signature, 2048 }
        };

        /// <summary>
        /// Mapping from algorithm to minimum <see cref="AsymmetricSecurityKey"/>.KeySize when verifying signatures.
        /// </summary>
        public static readonly Dictionary<string, int> DefaultMinimumAsymmetricKeySizeInBitsForVerifyingMap = new Dictionary<string, int>()
        {
            { SecurityAlgorithms.ECDSA_SHA256, 256 },
            { SecurityAlgorithms.ECDSA_SHA384, 256 },
            { SecurityAlgorithms.ECDSA_SHA512, 256 },
            { SecurityAlgorithms.RSA_SHA256, 1024 },
            { SecurityAlgorithms.RSA_SHA384, 1024 },
            { SecurityAlgorithms.RSA_SHA512, 1024 },
            { SecurityAlgorithms.RsaSha256Signature, 1024 },
            { SecurityAlgorithms.RsaSha384Signature, 1024 },
            { SecurityAlgorithms.RsaSha512Signature, 1024 }
        };

        /// <summary>
        /// Initializes a new instance of the <see cref="AsymmetricSignatureProvider"/> class used to create and verify signatures.
        /// </summary>
        /// <param name="key">The <see cref="AsymmetricSecurityKey"/> that will be used for cryptographic operations.</param>
        /// <param name="algorithm">The signature algorithm to apply.</param>
        /// <param name="willCreateSignatures">If this <see cref="AsymmetricSignatureProvider"/> is required to create signatures then set this to true.
        /// <para>
        /// Creating signatures requires that the <see cref="AsymmetricSecurityKey"/> has access to a private key. 
        /// Verifying signatures (the default), does not require access to the private key.
        /// </para>
        /// </param>
        /// <exception cref="ArgumentNullException">'key' is null.</exception>
        /// <exception cref="ArgumentOutOfRangeException">
        /// willCreateSignatures is true and <see cref="AsymmetricSecurityKey"/>.KeySize is less than the size corresponding to the given algorithm in <see cref="SignatureProviderFactory.MinimumAsymmetricKeySizeInBitsForSigningMap"/>.
        /// </exception>
        /// <exception cref="ArgumentOutOfRangeException">
        /// <see cref="AsymmetricSecurityKey"/>.KeySize is less than the size corresponding to the algorithm in <see cref="SignatureProviderFactory.MinimumAsymmetricKeySizeInBitsForVerifyingMap"/>. Note: this is always checked.
        /// </exception>
        /// <exception cref="ArgumentException">if 'algorithm" is not supported.</exception>
        /// <exception cref="ArgumentOutOfRangeException">if 'key' is not <see cref="RsaSecurityKey"/> or <see cref="X509SecurityKey"/>.</exception>
        public AsymmetricSignatureProvider(AsymmetricSecurityKey key, string algorithm, bool willCreateSignatures = false)
        {
            if (key == null)
                LogHelper.Throw(string.Format(CultureInfo.InvariantCulture, LogMessages.IDX10000, "AsymmetricSignatureProvider.key"), typeof(ArgumentNullException), EventLevel.Verbose);

            if (!IsSupportedAlgorithm(algorithm))
                LogHelper.Throw(string.Format(CultureInfo.InvariantCulture, LogMessages.IDX10640, algorithm ?? "null"), typeof(ArgumentException));

            _minimumAsymmetricKeySizeInBitsForSigningMap = new Dictionary<string, int>(DefaultMinimumAsymmetricKeySizeInBitsForSigningMap);
            _minimumAsymmetricKeySizeInBitsForVerifyingMap = new Dictionary<string, int>(DefaultMinimumAsymmetricKeySizeInBitsForVerifyingMap);

            ValidateAsymmetricSecurityKeySize(key, algorithm, willCreateSignatures);
            if (willCreateSignatures && !key.HasPrivateKey)
            {
                LogHelper.Throw(string.Format(CultureInfo.InvariantCulture, LogMessages.IDX10638, key.ToString()), typeof(InvalidOperationException));
            }

#if DNXCORE50
            ResolveDotNetCoreAsymmetricAlgorithm(key, algorithm, willCreateSignatures);
#else
            ResolveDotNetDesktopAsymmetricAlgorithm(key, algorithm, willCreateSignatures);
#endif
        }

        /// <summary>
        /// Gets the mapping from algorithm to the minimum <see cref="AsymmetricSecurityKey"/>.KeySize for creating signatures.
        /// </summary>
        public IReadOnlyDictionary<string, int> MinimumAsymmetricKeySizeInBitsForSigningMap
        {
            get
            {
                return _minimumAsymmetricKeySizeInBitsForSigningMap;
            }
        }

        /// <summary>
        /// Gets the mapping from algorithm to the minimum <see cref="AsymmetricSecurityKey"/>.KeySize for verifying signatures.
        /// </summary>
        public IReadOnlyDictionary<string, int> MinimumAsymmetricKeySizeInBitsForVerifyingMap
        {
            get
            {
                return _minimumAsymmetricKeySizeInBitsForVerifyingMap;
            }
        }

#if DNXCORE50
        protected virtual HashAlgorithmName GetHashAlgorithmName(string algorithm)
        {
            if (string.IsNullOrWhiteSpace(algorithm))
                LogHelper.Throw(string.Format(CultureInfo.InvariantCulture, LogMessages.IDX10000, "GetHashAlgorithmName.algorithm"), typeof(ArgumentNullException), EventLevel.Verbose);

            switch (algorithm)
            {
                case SecurityAlgorithms.SHA256:
                case SecurityAlgorithms.ECDSA_SHA256:
                case SecurityAlgorithms.RSA_SHA256:
                case SecurityAlgorithms.RsaSha256Signature:
                    return HashAlgorithmName.SHA256;

                case SecurityAlgorithms.SHA384:
                case SecurityAlgorithms.ECDSA_SHA384:
                case SecurityAlgorithms.RSA_SHA384:
                case SecurityAlgorithms.RsaSha384Signature:
                    return HashAlgorithmName.SHA384;

                case SecurityAlgorithms.SHA512:
                case SecurityAlgorithms.ECDSA_SHA512:
                case SecurityAlgorithms.RSA_SHA512:
                case SecurityAlgorithms.RsaSha512Signature:
                    return HashAlgorithmName.SHA512;
            }

            LogHelper.Throw(string.Format(CultureInfo.InvariantCulture, LogMessages.IDX10640, algorithm), typeof(ArgumentOutOfRangeException));
            return new HashAlgorithmName(null);
        }

        private void ResolveDotNetCoreAsymmetricAlgorithm(AsymmetricSecurityKey key, string algorithm, bool willCreateSignatures)
        {
            _hashAlgorithm = GetHashAlgorithmName(algorithm);
            RsaSecurityKey rsaKey = key as RsaSecurityKey;

            if (rsaKey != null)
            {
                _rsa = new RSACng();
                (_rsa as RSA).ImportParameters(rsaKey.Parameters);
                return;
            }

            X509SecurityKey x509Key = key as X509SecurityKey;
            if (x509Key != null)
            {
                if (willCreateSignatures)
                {
                    RSACryptoServiceProvider rsaCsp = x509Key.PrivateKey as RSACryptoServiceProvider;
                    if (rsaCsp != null)
                    {
                        _rsaCryptoServiceProviderProxy = new RSACryptoServiceProviderProxy(rsaCsp);
                    }
                    else
                    {
                        _rsa = x509Key.PrivateKey as RSA;
                    }
                }
                else
                {
                    _rsa = RSACertificateExtensions.GetRSAPublicKey(x509Key.Certificate);
                }
                return;
            }

            ECDsaSecurityKey ecdsaKey = key as ECDsaSecurityKey;
            if (ecdsaKey != null)
            {
                _ecdsaCng = new ECDsaCng(ecdsaKey.CngKey);
                return;
            }

            LogHelper.Throw(string.Format(CultureInfo.InvariantCulture, LogMessages.IDX10641, key.ToString()), typeof(ArgumentOutOfRangeException));
            return;
        }
#else
        protected virtual string GetHashAlgorithmString(string algorithm)
        {
            if (string.IsNullOrWhiteSpace(algorithm))
                LogHelper.Throw(string.Format(CultureInfo.InvariantCulture, LogMessages.IDX10000, "GetHashAlgorithm.algorithm"), typeof(ArgumentNullException), EventLevel.Verbose);

            switch (algorithm)
            {
                case SecurityAlgorithms.SHA256:
                case SecurityAlgorithms.ECDSA_SHA256:
                case SecurityAlgorithms.RSA_SHA256:
                case SecurityAlgorithms.RsaSha256Signature:
                    return SecurityAlgorithms.SHA256;

                case SecurityAlgorithms.SHA384:
                case SecurityAlgorithms.ECDSA_SHA384:
                case SecurityAlgorithms.RSA_SHA384:
                case SecurityAlgorithms.RsaSha384Signature:
                    return SecurityAlgorithms.SHA384;

                case SecurityAlgorithms.SHA512:
                case SecurityAlgorithms.ECDSA_SHA512:
                case SecurityAlgorithms.RSA_SHA512:
                case SecurityAlgorithms.RsaSha512Signature:
                    return SecurityAlgorithms.SHA512;
            }

            LogHelper.Throw(string.Format(CultureInfo.InvariantCulture, LogMessages.IDX10640, algorithm), typeof(ArgumentOutOfRangeException));
            return null;
        }

        private void ResolveDotNetDesktopAsymmetricAlgorithm(AsymmetricSecurityKey key, string algorithm, bool willCreateSignatures)
        {
            _hashAlgorithm = GetHashAlgorithmString(algorithm);
            RsaSecurityKey rsaKey = key as RsaSecurityKey;

            if (rsaKey != null)
            {
                _rsaCryptoServiceProvider = new RSACryptoServiceProvider();
                (_rsaCryptoServiceProvider as RSA).ImportParameters(rsaKey.Parameters);
                return;
            }

            X509SecurityKey x509Key = key as X509SecurityKey;
            if (x509Key != null)
            {
                if (willCreateSignatures)
                {
                    _rsaCryptoServiceProviderProxy = new RSACryptoServiceProviderProxy(x509Key.PrivateKey as RSACryptoServiceProvider);
                }
                else
                {
                    _rsaCryptoServiceProviderProxy = new RSACryptoServiceProviderProxy(x509Key.PublicKey.Key as RSACryptoServiceProvider);
                }
                return;
            }

            ECDsaSecurityKey ecdsaKey = key as ECDsaSecurityKey;
            if (ecdsaKey != null)
            {
                _ecdsaCng = new ECDsaCng(ecdsaKey.CngKey);
                _ecdsaCng.HashAlgorithm = new CngAlgorithm(_hashAlgorithm);
                return;
            }

            LogHelper.Throw(string.Format(CultureInfo.InvariantCulture, LogMessages.IDX10641, key.ToString()), typeof(ArgumentOutOfRangeException));
            return;
        }
#endif

        public override bool IsSupportedAlgorithm(string algorithm)
        {
            if (string.IsNullOrEmpty(algorithm))
                return false;

            switch (algorithm)
            {
                case SecurityAlgorithms.SHA256:
                case SecurityAlgorithms.SHA384:
                case SecurityAlgorithms.SHA512:
                case SecurityAlgorithms.ECDSA_SHA256:
                case SecurityAlgorithms.ECDSA_SHA384:
                case SecurityAlgorithms.ECDSA_SHA512:
                case SecurityAlgorithms.RSA_SHA256:
                case SecurityAlgorithms.RSA_SHA384:
                case SecurityAlgorithms.RSA_SHA512:
                case SecurityAlgorithms.RsaSha256Signature:
                case SecurityAlgorithms.RsaSha384Signature:
                case SecurityAlgorithms.RsaSha512Signature:
                    return true;

                default:
                    return false;
            }
        }

        /// <summary>
        /// Produces a signature over the 'input' using the <see cref="AsymmetricSecurityKey"/> and algorithm passed to <see cref="AsymmetricSignatureProvider( AsymmetricSecurityKey, string, bool )"/>.
        /// </summary>
        /// <param name="input">bytes to be signed.</param>
        /// <returns>a signature over the input.</returns>
        /// <exception cref="ArgumentNullException">'input' is null. </exception>
        /// <exception cref="ArgumentException">'input.Length' == 0. </exception>
        /// <exception cref="ObjectDisposedException">if <see cref="AsymmetricSignatureProvider.Dispose(bool)"/> has been called. </exception>
        /// <exception cref="InvalidOperationException">if the internal <see cref="AsymmetricSignatureFormatter"/> is null. This can occur if the constructor parameter 'willBeUsedforSigning' was not 'true'.</exception>
        /// <exception cref="InvalidOperationException">if the internal <see cref="HashAlgorithm"/> is null. This can occur if a derived type deletes it or does not create it.</exception>
        public override byte[] Sign(byte[] input)
        {
            if (input == null)
            {
                LogHelper.Throw(string.Format(CultureInfo.InvariantCulture, LogMessages.IDX10000, "Sign.input"), typeof(ArgumentNullException), EventLevel.Verbose);
            }

            if (input.Length == 0)
            {
                LogHelper.Throw(LogMessages.IDX10624, typeof(ArgumentException));
            }

            if (this.disposed)
            {
                LogHelper.Throw(GetType().ToString(), typeof(ObjectDisposedException));
            }

#if DNXCORE50
            if (_rsa != null)
                return _rsa.SignData(input, _hashAlgorithm, RSASignaturePadding.Pkcs1);
            else if (_rsaCryptoServiceProviderProxy != null)
                return _rsaCryptoServiceProviderProxy.SignData(input, _hashAlgorithm.Name);
            else if (_ecdsaCng != null)
                return _ecdsaCng.SignData(input, _hashAlgorithm);
#else
            if (_rsaCryptoServiceProvider != null)
                return _rsaCryptoServiceProvider.SignData(input, _hashAlgorithm);
            else if (_rsaCryptoServiceProviderProxy != null)
                return _rsaCryptoServiceProviderProxy.SignData(input, _hashAlgorithm);
            else if (_ecdsaCng != null)
                return _ecdsaCng.SignData(input);
#endif
            LogHelper.Throw(LogMessages.IDX10644, typeof(InvalidOperationException));
            return null;
        }

        /// <summary>
        /// Verifies that a signature over the' input' matches the signature.
        /// </summary>
        /// <param name="input">the bytes to generate the signature over.</param>
        /// <param name="signature">the value to verify against.</param>
        /// <returns>true if signature matches, false otherwise.</returns>
        /// <exception cref="ArgumentNullException">'input' is null.</exception>
        /// <exception cref="ArgumentNullException">'signature' is null.</exception>
        /// <exception cref="ArgumentException">'input.Length' == 0.</exception>
        /// <exception cref="ArgumentException">'signature.Length' == 0.</exception>
        /// <exception cref="ObjectDisposedException">if <see cref="AsymmetricSignatureProvider.Dispose(bool)"/> has been called. </exception>
        /// <exception cref="InvalidOperationException">if the internal <see cref="AsymmetricSignatureDeformatter"/> is null. This can occur if a derived type does not call the base constructor.</exception>
        /// <exception cref="InvalidOperationException">if the internal <see cref="HashAlgorithm"/> is null. This can occur if a derived type deletes it or does not create it.</exception>
        public override bool Verify(byte[] input, byte[] signature)
        {
            if (input == null)
            {
                LogHelper.Throw(string.Format(CultureInfo.InvariantCulture, LogMessages.IDX10000, "Verify.input"), typeof(ArgumentNullException), EventLevel.Verbose);
            }

            if (signature == null)
            {
                LogHelper.Throw(string.Format(CultureInfo.InvariantCulture, LogMessages.IDX10000, "Verify.signature"), typeof(ArgumentNullException), EventLevel.Verbose);
            }

            if (input.Length == 0)
            {
                LogHelper.Throw(LogMessages.IDX10625, typeof(ArgumentException));
            }

            if (signature.Length == 0)
            {
                LogHelper.Throw(LogMessages.IDX10626, typeof(ArgumentException));
            }

            if (this.disposed)
            {
                LogHelper.Throw(GetType().ToString(), typeof(ObjectDisposedException));
            }

            if (_hashAlgorithm == null)
            {
                LogHelper.Throw(LogMessages.IDX10621, typeof(InvalidOperationException));
            }

#if DNXCORE50
            if (_rsa != null)
                return _rsa.VerifyData(input, signature, _hashAlgorithm, RSASignaturePadding.Pkcs1);
            else if (_rsaCryptoServiceProviderProxy != null)
                return _rsaCryptoServiceProviderProxy.VerifyData(input, _hashAlgorithm.Name, signature);
            else if (_ecdsaCng != null)
                return _ecdsaCng.VerifyData(input, signature, _hashAlgorithm);
#else
            if (_rsaCryptoServiceProvider != null)
                return _rsaCryptoServiceProvider.VerifyData(input, _hashAlgorithm, signature);
            else if (_rsaCryptoServiceProviderProxy != null)
                return _rsaCryptoServiceProviderProxy.VerifyData(input, _hashAlgorithm, signature);
            else if (_ecdsaCng != null)
                return _ecdsaCng.VerifyData(input, signature);
#endif

            LogHelper.Throw(LogMessages.IDX10644, typeof(InvalidOperationException));
            return false;
        }

        /// <summary>
        /// Validates that the asymmetric key size is more than the allowed minimum
        /// </summary>
        /// <param name="key">asymmetric key to validate</param>
        /// <param name="algorithm">algorithm for which this key will be used</param>
        /// <param name="willCreateSignatures">whether they key will be used for creating signatures</param>
        public void ValidateAsymmetricSecurityKeySize(SecurityKey key, string algorithm, bool willCreateSignatures)
        {
            if (willCreateSignatures)
            {
                if (MinimumAsymmetricKeySizeInBitsForSigningMap.ContainsKey(algorithm) && key.KeySize < MinimumAsymmetricKeySizeInBitsForSigningMap[algorithm])
                {
                    LogHelper.Throw(string.Format(CultureInfo.InvariantCulture, LogMessages.IDX10630, key.GetType(), MinimumAsymmetricKeySizeInBitsForSigningMap, key.KeySize), typeof(ArgumentOutOfRangeException));
                }
            }

            if (MinimumAsymmetricKeySizeInBitsForVerifyingMap.ContainsKey(algorithm) && key.KeySize < MinimumAsymmetricKeySizeInBitsForVerifyingMap[algorithm])
            {
                LogHelper.Throw(string.Format(CultureInfo.InvariantCulture, LogMessages.IDX10631, key.GetType(), MinimumAsymmetricKeySizeInBitsForVerifyingMap, key.KeySize), typeof(ArgumentOutOfRangeException));
            }
        }

        /// <summary>
        /// Calls <see cref="HashAlgorithm.Dispose()"/> to release this managed resources.
        /// </summary>
        /// <param name="disposing">true, if called from Dispose(), false, if invoked inside a finalizer.</param>
        protected override void Dispose(bool disposing)
        {
            if (!this.disposed)
            {
                if (disposing)
                {
                    this.disposed = true;
                }
            }
        }
    }
}
