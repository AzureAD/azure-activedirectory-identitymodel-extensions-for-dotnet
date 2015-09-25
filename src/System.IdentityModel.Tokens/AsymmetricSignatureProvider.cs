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

using System.Globalization;
using System.Security.Cryptography;
using System.Security.Cryptography.X509Certificates;

namespace System.IdentityModel.Tokens
{
    /// <summary>
    /// Provides signing and verifying operations when working with an <see cref="AsymmetricSecurityKey"/>
    /// </summary>
    public class AsymmetricSignatureProvider : SignatureProvider
    {
        private bool disposed;
#if DNXCORE50
        private RSACng rsaCng;
        private HashAlgorithmName hash;
#else
        private RSACryptoServiceProvider rsaCryptoServiceProvider;
        private HashAlgorithm hash;
        private RSACryptoServiceProviderProxy rsaCryptoServiceProviderProxy;
#endif

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
        /// willCreateSignatures is true and <see cref="AsymmetricSecurityKey"/>.KeySize is less than <see cref="SignatureProviderFactory.MinimumAsymmetricKeySizeInBitsForSigning"/>.
        /// </exception>
        /// <exception cref="ArgumentOutOfRangeException">
        /// <see cref="AsymmetricSecurityKey"/>.KeySize is less than <see cref="SignatureProviderFactory.MinimumAsymmetricKeySizeInBitsForVerifying"/>. Note: this is always checked.
        /// </exception>
        /// <exception cref="ArgumentException">if 'algorithm" is not supported.</exception>
        /// <exception cref="ArgumentOutOfRangeException">if 'key' is not <see cref="RsaSecurityKey"/> or <see cref="X509SecurityKey"/>.</exception>
        public AsymmetricSignatureProvider(AsymmetricSecurityKey key, string algorithm, bool willCreateSignatures = false)
        {
            if (key == null)
                throw new ArgumentNullException("key");

            if (!IsSupportedAlgorithm(algorithm))
                throw new ArgumentException(string.Format(CultureInfo.InvariantCulture, LogMessages.IDX10640, algorithm ?? "null"));

            if (willCreateSignatures)
            {
                if (key.KeySize < SignatureProviderFactory.MinimumAsymmetricKeySizeInBitsForSigning)
                {
                    throw new ArgumentOutOfRangeException("key.KeySize", key.KeySize, string.Format(CultureInfo.InvariantCulture, LogMessages.IDX10631, key.GetType(), SignatureProviderFactory.MinimumAsymmetricKeySizeInBitsForSigning));
                }

                if (!key.HasPrivateKey)
                {
                    throw new InvalidOperationException(string.Format(CultureInfo.InvariantCulture, LogMessages.IDX10638, key.ToString()));
                }
            }

            if (key.KeySize < SignatureProviderFactory.MinimumAsymmetricKeySizeInBitsForVerifying)
            {
                throw new ArgumentOutOfRangeException("key.KeySize", key.KeySize, string.Format(CultureInfo.InvariantCulture, LogMessages.IDX10630, key.GetType(), SignatureProviderFactory.MinimumAsymmetricKeySizeInBitsForVerifying));
            }

#if DNXCORE50
            hash = GetHashAlgorithmName(algorithm);
#else
            hash = GetHashAlgorithm(algorithm);
#endif
            RsaSecurityKey rsaKey = key as RsaSecurityKey;

            if (rsaKey != null)
            {
#if DNXCORE50
                rsaCng = new RSACng();
                (rsaCng as RSA).ImportParameters(rsaKey.Parameters);
#else
                rsaCryptoServiceProvider = new RSACryptoServiceProvider();
                (rsaCryptoServiceProvider as RSA).ImportParameters(rsaKey.Parameters);
#endif
                return;    
            }

            X509SecurityKey x509Key = key as X509SecurityKey;
            if (x509Key != null)
            {

#if DNXCORE50
                if (willCreateSignatures)
                {
                    rsaCng = RSACertificateExtensions.GetRSAPrivateKey(x509Key.Certificate) as RSACng;
                }
                else
                {
                    rsaCng = RSACertificateExtensions.GetRSAPublicKey(x509Key.Certificate) as RSACng;
                }
                return;
#else
                RSACryptoServiceProvider rsa = null;
                if (willCreateSignatures)
                {
                    rsa = x509Key.PrivateKey as RSACryptoServiceProvider;
                }
                else
                {
                    rsa = x509Key.PublicKey.Key as RSACryptoServiceProvider;
                }
                rsaCryptoServiceProviderProxy = new RSACryptoServiceProviderProxy(rsa);
                return;
#endif
            }

            throw new ArgumentOutOfRangeException(string.Format(CultureInfo.InvariantCulture, LogMessages.IDX10641, key.ToString()));
        }

        protected virtual HashAlgorithm GetHashAlgorithm(string algorithm)
        {
            if (string.IsNullOrWhiteSpace(algorithm))
                throw new ArgumentNullException("algorithm");

            switch (algorithm)
            {
                case SecurityAlgorithms.RsaSha1Signature:
                    return SHA1.Create();

                case SecurityAlgorithms.ECDSA_SHA256:
                case SecurityAlgorithms.HMAC_SHA256:
                case SecurityAlgorithms.RSA_SHA256:
                case SecurityAlgorithms.RsaSha256Signature:
                    return SHA256.Create();

                case SecurityAlgorithms.ECDSA_SHA384:
                case SecurityAlgorithms.HMAC_SHA384:
                case SecurityAlgorithms.RSA_SHA384:
                case SecurityAlgorithms.RsaSha384Signature:
                    return SHA384.Create();

                case SecurityAlgorithms.RsaSha512Signature:
                case SecurityAlgorithms.RSA_SHA512:
                case SecurityAlgorithms.ECDSA_SHA512:
                case SecurityAlgorithms.HMAC_SHA512:
                    return SHA512.Create();

                default:
                    throw new ArgumentOutOfRangeException(string.Format(CultureInfo.InvariantCulture, LogMessages.IDX10640, algorithm));
            }
        }

#if DNXCORE50
        protected virtual HashAlgorithmName GetHashAlgorithmName(string algorithm)
        {
            if (string.IsNullOrWhiteSpace(algorithm))
                throw new ArgumentNullException("algorithm");

            switch (algorithm)
            {
                case SecurityAlgorithms.RsaSha1Signature:
                    return HashAlgorithmName.SHA1;

                case SecurityAlgorithms.ECDSA_SHA256:
                case SecurityAlgorithms.HMAC_SHA256:
                case SecurityAlgorithms.RSA_SHA256:
                case SecurityAlgorithms.RsaSha256Signature:
                    return HashAlgorithmName.SHA256;

                case SecurityAlgorithms.ECDSA_SHA384:
                case SecurityAlgorithms.HMAC_SHA384:
                case SecurityAlgorithms.RSA_SHA384:
                case SecurityAlgorithms.RsaSha384Signature:
                    return HashAlgorithmName.SHA384;

                case SecurityAlgorithms.RsaSha512Signature:
                case SecurityAlgorithms.RSA_SHA512:
                case SecurityAlgorithms.ECDSA_SHA512:
                case SecurityAlgorithms.HMAC_SHA512:
                    return HashAlgorithmName.SHA512;

                default:
                    throw new ArgumentOutOfRangeException(string.Format(CultureInfo.InvariantCulture, LogMessages.IDX10640, algorithm));
            }
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
                case SecurityAlgorithms.HMAC_SHA256:
                case SecurityAlgorithms.HMAC_SHA384:
                case SecurityAlgorithms.HMAC_SHA512:
                case SecurityAlgorithms.RSA_SHA256:
                case SecurityAlgorithms.RSA_SHA384:
                case SecurityAlgorithms.RSA_SHA512:
                case SecurityAlgorithms.RsaSha1Signature:
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
                throw new ArgumentNullException("input");
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
            if (rsaCng != null)
                return rsaCng.SignData(input, hash, RSASignaturePadding.Pkcs1);
#else
            if (rsaCryptoServiceProvider != null)
                return rsaCryptoServiceProvider.SignData(input, hash);
            else if (rsaCryptoServiceProviderProxy != null)
                return rsaCryptoServiceProviderProxy.SignData(input, hash);
#endif

            throw new InvalidOperationException("Crypto not supported");
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
                throw new ArgumentNullException("input");
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
            if (rsaCng != null)
                return rsaCng.VerifyData(input, signature, hash, RSASignaturePadding.Pkcs1);
#else
            if (rsaCryptoServiceProvider != null)
                return rsaCryptoServiceProvider.VerifyData(input, hash, signature);
            else if (rsaCryptoServiceProviderProxy != null)
                return rsaCryptoServiceProviderProxy.VerifyData(input, hash, signature);
#endif

            throw new InvalidOperationException("Crypto not supported");
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

#if POST_RC
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
}
