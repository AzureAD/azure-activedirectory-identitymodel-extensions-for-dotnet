//-----------------------------------------------------------------------
// Copyright (c) Microsoft Open Technologies, Inc.
// All Rights Reserved
// Apache License 2.0
//
// Licensed under the Apache License, Version 2.0 (the "License");
// you may not use this file except in compliance with the License.
// You may obtain a copy of the License at
// 
// http://www.apache.org/licenses/LICENSE-2.0
// 
// Unless required by applicable law or agreed to in writing, software
// distributed under the License is distributed on an "AS IS" BASIS,
// WITHOUT WARRANTIES OR CONDITIONS OF ANY KIND, either express or implied.
// See the License for the specific language governing permissions and
// limitations under the License.
//-----------------------------------------------------------------------

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
        private RSA rsa;
        private HashAlgorithmName hash;
        private ECDsa ecdsaCng;
#else
        private RSACryptoServiceProvider rsaCryptoServiceProvider;
        private HashAlgorithm hash;
#endif
        private RSACryptoServiceProviderProxy rsaCryptoServiceProviderProxy;
        private IReadOnlyDictionary<string, int> minimumAsymmetricKeySizeInBitsForSigningMap;
        private IReadOnlyDictionary<string, int> minimumAsymmetricKeySizeInBitsForVerifyingMap;

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
                throw new ArgumentException(string.Format(CultureInfo.InvariantCulture, LogMessages.IDX10640, algorithm ?? "null"));

            minimumAsymmetricKeySizeInBitsForSigningMap = new Dictionary<string, int>(DefaultMinimumAsymmetricKeySizeInBitsForSigningMap);
            minimumAsymmetricKeySizeInBitsForVerifyingMap = new Dictionary<string, int>(DefaultMinimumAsymmetricKeySizeInBitsForVerifyingMap);

            ValidateAsymmetricSecurityKeySize(key, algorithm, willCreateSignatures);
            if (willCreateSignatures && !key.HasPrivateKey)
            {
                throw new InvalidOperationException(string.Format(CultureInfo.InvariantCulture, LogMessages.IDX10638, key.ToString()));
            }

            bool algorithmResolved = false;
#if DNXCORE50
            algorithmResolved = ResolveDotNetCoreAsymmetricAlgorithm(key, algorithm, willCreateSignatures);
#else
            algorithmResolved = ResolveDotNetDesktopAsymmetricAlgorithm(key, algorithm, willCreateSignatures);
#endif
            if (!algorithmResolved)
                throw new ArgumentOutOfRangeException(string.Format(CultureInfo.InvariantCulture, LogMessages.IDX10641, key.ToString()));
        }

        /// <summary>
        /// Gets the mapping from algorithm to the minimum <see cref="AsymmetricSecurityKey"/>.KeySize for creating signatures.
        /// </summary>
        public IReadOnlyDictionary<string, int> MinimumAsymmetricKeySizeInBitsForSigningMap
        {
            get
            {
                return minimumAsymmetricKeySizeInBitsForSigningMap;
            }
        }

        /// <summary>
        /// Gets the mapping from algorithm to the minimum <see cref="AsymmetricSecurityKey"/>.KeySize for verifying signatures.
        /// </summary>
        public IReadOnlyDictionary<string, int> MinimumAsymmetricKeySizeInBitsForVerifyingMap
        {
            get
            {
                return minimumAsymmetricKeySizeInBitsForVerifyingMap;
            }
        }


#if DNXCORE50
        protected virtual HashAlgorithmName GetHashAlgorithmName(string algorithm)
        {
            if (string.IsNullOrWhiteSpace(algorithm))
                LogHelper.Throw(string.Format(CultureInfo.InvariantCulture, LogMessages.IDX10000, "GetHashAlgorithmName.algorithm"), typeof(ArgumentNullException), EventLevel.Verbose);

            switch (algorithm)
            {
                case SecurityAlgorithms.ECDSA_SHA256:
                case SecurityAlgorithms.RSA_SHA256:
                case SecurityAlgorithms.RsaSha256Signature:
                    return HashAlgorithmName.SHA256;

                case SecurityAlgorithms.ECDSA_SHA384:
                case SecurityAlgorithms.RSA_SHA384:
                case SecurityAlgorithms.RsaSha384Signature:
                    return HashAlgorithmName.SHA384;

                case SecurityAlgorithms.ECDSA_SHA512:
                case SecurityAlgorithms.RSA_SHA512:
                case SecurityAlgorithms.RsaSha512Signature:
                    return HashAlgorithmName.SHA512;

                default:
                    throw new ArgumentOutOfRangeException(string.Format(CultureInfo.InvariantCulture, LogMessages.IDX10640, algorithm));
            }
        }

        private bool ResolveDotNetCoreAsymmetricAlgorithm(AsymmetricSecurityKey key, string algorithm, bool willCreateSignatures)
        {
            hash = GetHashAlgorithmName(algorithm);
            RsaSecurityKey rsaKey = key as RsaSecurityKey;

            if (rsaKey != null)
            {
                rsa = new RSACng();
                (rsa as RSA).ImportParameters(rsaKey.Parameters);
                return true;    
            }

            X509SecurityKey x509Key = key as X509SecurityKey;
            if (x509Key != null)
            {
                if (willCreateSignatures)
                {
                    RSACryptoServiceProvider rsaCsp = x509Key.PrivateKey as RSACryptoServiceProvider;
                    if (rsaCsp != null)
                    {
                        rsaCryptoServiceProviderProxy = new RSACryptoServiceProviderProxy(rsaCsp);
                    }
                    else
                    {
                        rsa = x509Key.PrivateKey as RSA;
                    }
                }
                else
                {
                    rsa = RSACertificateExtensions.GetRSAPublicKey(x509Key.Certificate);
                }
                return true;
            }

            ECDsaSecurityKey ecdsaKey = key as ECDsaSecurityKey;
            if (ecdsaKey != null)
            {
                ecdsaCng = new ECDsaCng(ecdsaKey.CngKey);
                return true;
            }
            return false;
        }
#else
        protected virtual HashAlgorithm GetHashAlgorithm(string algorithm)
        {
            if (string.IsNullOrWhiteSpace(algorithm))
                LogHelper.Throw(string.Format(CultureInfo.InvariantCulture, LogMessages.IDX10000, "GetHashAlgorithm.algorithm"), typeof(ArgumentNullException), EventLevel.Verbose);

            switch (algorithm)
            {
                case SecurityAlgorithms.ECDSA_SHA256:
                case SecurityAlgorithms.RSA_SHA256:
                case SecurityAlgorithms.RsaSha256Signature:
                    return SHA256.Create();

                case SecurityAlgorithms.ECDSA_SHA384:
                case SecurityAlgorithms.RSA_SHA384:
                case SecurityAlgorithms.RsaSha384Signature:
                    return SHA384.Create();

                case SecurityAlgorithms.ECDSA_SHA512:
                case SecurityAlgorithms.RSA_SHA512:
                case SecurityAlgorithms.RsaSha512Signature:
                    return SHA512.Create();

                default:
                    throw new ArgumentOutOfRangeException(string.Format(CultureInfo.InvariantCulture, LogMessages.IDX10640, algorithm));
            }
        }

        private bool ResolveDotNetDesktopAsymmetricAlgorithm(AsymmetricSecurityKey key, string algorithm, bool willCreateSignatures)
        {
            hash = GetHashAlgorithm(algorithm);

            RsaSecurityKey rsaKey = key as RsaSecurityKey;

            if (rsaKey != null)
            {
                rsaCryptoServiceProvider = new RSACryptoServiceProvider();
                (rsaCryptoServiceProvider as RSA).ImportParameters(rsaKey.Parameters);
                return true;
            }

            X509SecurityKey x509Key = key as X509SecurityKey;
            if (x509Key != null)
            {
                if (willCreateSignatures)
                {
                    rsaCryptoServiceProviderProxy = new RSACryptoServiceProviderProxy(x509Key.PrivateKey as RSACryptoServiceProvider);
                }
                else
                {
                    rsaCryptoServiceProviderProxy = new RSACryptoServiceProviderProxy(x509Key.PublicKey.Key as RSACryptoServiceProvider);
                }
                return true;
            }

            return false;
        }
#endif

        public override bool IsSupportedAlgorithm(string algorithm)
        {
            if (string.IsNullOrEmpty(algorithm))
                return false;

            switch (algorithm)
            {
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
                throw new ArgumentException(LogMessages.IDX10624);
            }

            if (this.disposed)
            {
                throw new ObjectDisposedException(GetType().ToString());
            }
#if DNXCORE50
            if (rsa != null)
                return rsa.SignData(input, hash, RSASignaturePadding.Pkcs1);
            else if (rsaCryptoServiceProviderProxy != null)
                return rsaCryptoServiceProviderProxy.SignData(input, hash.Name);
            else if (ecdsaCng != null)
                return ecdsaCng.SignData(input, hash);
#else
            if (rsaCryptoServiceProvider != null)
                return rsaCryptoServiceProvider.SignData(input, hash);
            else if (rsaCryptoServiceProviderProxy != null)
                return rsaCryptoServiceProviderProxy.SignData(input, hash);
#endif

            throw new InvalidOperationException(LogMessages.IDX10644);
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
                throw new ArgumentNullException("signature");
            }

            if (input.Length == 0)
            {
                throw new ArgumentException(LogMessages.IDX10625);
            }

            if (signature.Length == 0)
            {
                throw new ArgumentException(LogMessages.IDX10626);
            }

            if (this.disposed)
            {
                throw new ObjectDisposedException(GetType().ToString());
            }

            if (this.hash == null)
            {
                throw new InvalidOperationException(LogMessages.IDX10621);
            }
#if DNXCORE50
            if (rsa != null)
                return rsa.VerifyData(input, signature, hash, RSASignaturePadding.Pkcs1);
            else if (rsaCryptoServiceProviderProxy != null)
                return rsaCryptoServiceProviderProxy.VerifyData(input, hash.Name, signature);
            else if (ecdsaCng != null)
                return ecdsaCng.VerifyData(input, signature, hash);
#else
            if (rsaCryptoServiceProvider != null)
                return rsaCryptoServiceProvider.VerifyData(input, hash, signature);
            else if (rsaCryptoServiceProviderProxy != null)
                return rsaCryptoServiceProviderProxy.VerifyData(input, hash, signature);
#endif

            throw new InvalidOperationException(LogMessages.IDX10644);
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
                    throw new ArgumentOutOfRangeException("key.KeySize", key.KeySize, string.Format(CultureInfo.InvariantCulture, LogMessages.IDX10630, key.GetType(), MinimumAsymmetricKeySizeInBitsForSigningMap));
                }
            }

            if (MinimumAsymmetricKeySizeInBitsForVerifyingMap.ContainsKey(algorithm) && key.KeySize < MinimumAsymmetricKeySizeInBitsForVerifyingMap[algorithm])
            {
                throw new ArgumentOutOfRangeException("key.KeySize", key.KeySize, string.Format(CultureInfo.InvariantCulture, LogMessages.IDX10631, key.GetType(), MinimumAsymmetricKeySizeInBitsForVerifyingMap));
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
#if !DNXCORE50
                if (hash != null)
                {
                    hash.Dispose();
                    hash = null;
                }
#endif
            }
        }
    }
}
