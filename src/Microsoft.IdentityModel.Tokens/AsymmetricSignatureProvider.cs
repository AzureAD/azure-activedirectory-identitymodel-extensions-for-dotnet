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
using System.Collections.Generic;
using System.Security.Cryptography;
using Microsoft.IdentityModel.Logging;

namespace Microsoft.IdentityModel.Tokens
{
    /// <summary>
    /// Provides signing and verifying operations when working with an <see cref="AsymmetricSecurityKey"/>
    /// </summary>
    public class AsymmetricSignatureProvider : SignatureProvider
    {
#if NETSTANDARD1_4
        private ECDsa _ecdsa;
        private RSA _rsa;
        private HashAlgorithmName _hashAlgorithmName;
#elif NET46
        private ECDsaCng _ecdsa;
        private RSACng _rsa;
        private HashAlgorithmName _hashAlgorithmName;
        private RSACryptoServiceProviderProxy _rsaCryptoServiceProviderProxy;
        private string _hashAlgorithmString;
#else
        private ECDsaCng _ecdsa;
        private RSACryptoServiceProviderProxy _rsaCryptoServiceProviderProxy;
        private string _hashAlgorithmString;
#endif
        private bool _disposeRsa;
        private bool _disposeEcdsa;
        private bool _disposed;
        private IReadOnlyDictionary<string, int> _minimumAsymmetricKeySizeInBitsForSigningMap;
        private IReadOnlyDictionary<string, int> _minimumAsymmetricKeySizeInBitsForVerifyingMap;

        /// <summary>
        /// Mapping from algorithm to minimum <see cref="AsymmetricSecurityKey"/>.KeySize when creating signatures.
        /// </summary>
        public static readonly Dictionary<string, int> DefaultMinimumAsymmetricKeySizeInBitsForSigningMap = new Dictionary<string, int>()
        {
            { SecurityAlgorithms.EcdsaSha256, 256 },
            { SecurityAlgorithms.EcdsaSha384, 256 },
            { SecurityAlgorithms.EcdsaSha512, 256 },
            { SecurityAlgorithms.RsaSha256, 2048 },
            { SecurityAlgorithms.RsaSha384, 2048 },
            { SecurityAlgorithms.RsaSha512, 2048 },
            { SecurityAlgorithms.RsaSha256Signature, 2048 },
            { SecurityAlgorithms.RsaSha384Signature, 2048 },
            { SecurityAlgorithms.RsaSha512Signature, 2048 }
        };

        /// <summary>
        /// Mapping from algorithm to minimum <see cref="AsymmetricSecurityKey"/>.KeySize when verifying signatures.
        /// </summary>
        public static readonly Dictionary<string, int> DefaultMinimumAsymmetricKeySizeInBitsForVerifyingMap = new Dictionary<string, int>()
        {
            { SecurityAlgorithms.EcdsaSha256, 256 },
            { SecurityAlgorithms.EcdsaSha384, 256 },
            { SecurityAlgorithms.EcdsaSha512, 256 },
            { SecurityAlgorithms.RsaSha256, 1024 },
            { SecurityAlgorithms.RsaSha384, 1024 },
            { SecurityAlgorithms.RsaSha512, 1024 },
            { SecurityAlgorithms.RsaSha256Signature, 1024 },
            { SecurityAlgorithms.RsaSha384Signature, 1024 },
            { SecurityAlgorithms.RsaSha512Signature, 1024 }
        };

        /// <summary>
        /// Initializes a new instance of the <see cref="AsymmetricSignatureProvider"/> class used to create and verify signatures.
        /// </summary>
        /// <param name="key">The <see cref="SecurityKey"/> that will be used for signature operations.<see cref="SecurityKey"/></param>
        /// <param name="algorithm">The signature algorithm to apply.</param>
        public AsymmetricSignatureProvider(SecurityKey key, string algorithm)
            : this(key, algorithm, false)
        {
        }

        /// <summary>
        /// Initializes a new instance of the <see cref="AsymmetricSignatureProvider"/> class used to create and verify signatures.
        /// </summary>
        /// <param name="key">The <see cref="SecurityKey"/> that will be used for signature operations.</param>
        /// <param name="algorithm">The signature algorithm to apply.</param>
        /// <param name="willCreateSignatures">Whether this <see cref="AsymmetricSignatureProvider"/> is required to create signatures then set this to true.</param>
        /// <para>
        /// Creating signatures requires that the <see cref="SecurityKey"/> has access to a private key.
        /// Verifying signatures (the default), does not require access to the private key.
        /// </para>
        /// <exception cref="ArgumentNullException">'key' is null.</exception>
        /// <exception cref="ArgumentOutOfRangeException">
        /// willCreateSignatures is true and <see cref="SecurityKey"/>.KeySize is less than the size corresponding to the given algorithm in <see cref="AsymmetricSignatureProvider.MinimumAsymmetricKeySizeInBitsForSigningMap"/>.
        /// </exception>
        /// <exception cref="ArgumentOutOfRangeException">
        /// <see cref="SecurityKey"/>.KeySize is less than the size corresponding to the algorithm in <see cref="AsymmetricSignatureProvider.MinimumAsymmetricKeySizeInBitsForVerifyingMap"/>. Note: this is always checked.
        /// </exception>
        /// <exception cref="ArgumentException">If <see cref="SecurityKey"/> and algorithm pair are not supported.</exception>
        /// <exception cref="ArgumentOutOfRangeException">If the runtime is unable to create a suitable cryptographic provider.</exception>
        public AsymmetricSignatureProvider(SecurityKey key, string algorithm, bool willCreateSignatures)
            : base(key, algorithm)
        {
            if (key == null)
                throw LogHelper.LogArgumentNullException("key");

            _minimumAsymmetricKeySizeInBitsForSigningMap = new Dictionary<string, int>(DefaultMinimumAsymmetricKeySizeInBitsForSigningMap);
            _minimumAsymmetricKeySizeInBitsForVerifyingMap = new Dictionary<string, int>(DefaultMinimumAsymmetricKeySizeInBitsForVerifyingMap);
            if (willCreateSignatures && FoundPrivateKey(key) == PrivateKeyStatus.DoesNotExist)
                throw LogHelper.LogExceptionMessage(new InvalidOperationException(LogHelper.FormatInvariant(LogMessages.IDX10638, key)));

            if (!key.CryptoProviderFactory.IsSupportedAlgorithm(algorithm, key))
                throw LogHelper.LogExceptionMessage(new NotSupportedException(LogHelper.FormatInvariant(LogMessages.IDX10634, (algorithm ?? "null"), key)));

            ValidateAsymmetricSecurityKeySize(key, algorithm, willCreateSignatures);
            ResolveAsymmetricAlgorithm(key, algorithm, willCreateSignatures);
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

        private PrivateKeyStatus FoundPrivateKey(SecurityKey key)
        {
            AsymmetricSecurityKey asymmetricSecurityKey = key as AsymmetricSecurityKey;
            if (asymmetricSecurityKey != null)
                return asymmetricSecurityKey.PrivateKeyStatus;

            JsonWebKey jsonWebKey = key as JsonWebKey;
            if (jsonWebKey != null)
                return jsonWebKey.HasPrivateKey ? PrivateKeyStatus.Exists : PrivateKeyStatus.DoesNotExist;

            return PrivateKeyStatus.Unknown;
        }

#if NETSTANDARD1_4 || NET46
        /// <summary>
        /// Returns the <see cref="HashAlgorithmName"/> instance.
        /// </summary>
        /// <param name="algorithm">The hash algorithm to use to create the hash value.</param>
        protected virtual HashAlgorithmName GetHashAlgorithmName(string algorithm)
        {
            if (string.IsNullOrWhiteSpace(algorithm))
                throw LogHelper.LogArgumentNullException("algorithm");

            switch (algorithm)
            {
                case SecurityAlgorithms.EcdsaSha256:
                case SecurityAlgorithms.EcdsaSha256Signature:
                case SecurityAlgorithms.RsaSha256:
                case SecurityAlgorithms.RsaSha256Signature:
                    return HashAlgorithmName.SHA256;

                case SecurityAlgorithms.EcdsaSha384:
                case SecurityAlgorithms.EcdsaSha384Signature:
                case SecurityAlgorithms.RsaSha384:
                case SecurityAlgorithms.RsaSha384Signature:
                    return HashAlgorithmName.SHA384;

                case SecurityAlgorithms.EcdsaSha512:
                case SecurityAlgorithms.EcdsaSha512Signature:
                case SecurityAlgorithms.RsaSha512:
                case SecurityAlgorithms.RsaSha512Signature:
                    return HashAlgorithmName.SHA512;
            }

            throw LogHelper.LogExceptionMessage(new ArgumentOutOfRangeException(nameof(algorithm), LogHelper.FormatInvariant(LogMessages.IDX10652, algorithm)));
        }
#endif
        /// <summary>
        /// Returns the algorithm name.
        /// </summary>
        /// <param name="algorithm">The hash algorithm to use to create the hash value.</param>
        protected virtual string GetHashAlgorithmString(string algorithm)
        {
            if (string.IsNullOrWhiteSpace(algorithm))
                throw LogHelper.LogArgumentNullException("algorithm");

            switch (algorithm)
            {
                case SecurityAlgorithms.EcdsaSha256:
                case SecurityAlgorithms.EcdsaSha256Signature:
                case SecurityAlgorithms.RsaSha256:
                case SecurityAlgorithms.RsaSha256Signature:
                    return SecurityAlgorithms.Sha256;

                case SecurityAlgorithms.EcdsaSha384:
                case SecurityAlgorithms.EcdsaSha384Signature:
                case SecurityAlgorithms.RsaSha384:
                case SecurityAlgorithms.RsaSha384Signature:
                    return SecurityAlgorithms.Sha384;

                case SecurityAlgorithms.EcdsaSha512:
                case SecurityAlgorithms.EcdsaSha512Signature:
                case SecurityAlgorithms.RsaSha512:
                case SecurityAlgorithms.RsaSha512Signature:
                    return SecurityAlgorithms.Sha512;
            }

            throw LogHelper.LogExceptionMessage(new ArgumentException(LogHelper.FormatInvariant(LogMessages.IDX10652, algorithm), nameof(algorithm)));
        }

        private void ResolveAsymmetricAlgorithm(SecurityKey key, string algorithm, bool willCreateSignatures)
        {
            if (key == null)
                throw LogHelper.LogArgumentNullException("key");

            if (string.IsNullOrWhiteSpace(algorithm))
                throw LogHelper.LogArgumentNullException("algorithm");

#if NETSTANDARD1_4 || NET46
            _hashAlgorithmName = GetHashAlgorithmName(algorithm);
#endif

#if NET45 || NET451 || NET46
            _hashAlgorithmString = GetHashAlgorithmString(algorithm);
#endif

            var rsaAlgorithm = Utility.ResolveRsaAlgorithm(key, algorithm, willCreateSignatures);
            if (rsaAlgorithm != null)
            {
#if NETSTANDARD1_4 || NET46
                if (rsaAlgorithm.rsa != null)
                {
                    _rsa = rsaAlgorithm.rsa;
                    _disposeRsa = rsaAlgorithm.dispose;
                    return;
                }
#endif

#if NET45 || NET451 || NET46
                if (rsaAlgorithm.rsaCryptoServiceProviderProxy != null)
                {
                    _rsaCryptoServiceProviderProxy = rsaAlgorithm.rsaCryptoServiceProviderProxy;
                    _disposeRsa = rsaAlgorithm.dispose;
                    return;
                }
#endif

                throw LogHelper.LogExceptionMessage(new NotSupportedException(LogHelper.FormatInvariant(LogMessages.IDX10641, key)));
            }

            var ecdsaAlgorithm = Utility.ResolveECDsaAlgorithm(key, algorithm, willCreateSignatures);
            if (ecdsaAlgorithm != null && ecdsaAlgorithm.ecdsa != null)
            {
                _ecdsa = ecdsaAlgorithm.ecdsa;
                _disposeEcdsa = ecdsaAlgorithm.dispose;

#if NET45 || NET451 || NET46
                _ecdsa.HashAlgorithm = new CngAlgorithm(_hashAlgorithmString);
#endif
                return;
            }

            throw LogHelper.LogExceptionMessage(new NotSupportedException(LogHelper.FormatInvariant(LogMessages.IDX10641, key)));
        }

        /// <summary>
        /// Produces a signature over the 'input' using the <see cref="AsymmetricSecurityKey"/> and algorithm passed to <see cref="AsymmetricSignatureProvider( SecurityKey, string, bool )"/>.
        /// </summary>
        /// <param name="input">The bytes to be signed.</param>
        /// <returns>A signature over the input.</returns>
        /// <exception cref="ArgumentNullException">'input' is null. </exception>
        /// <exception cref="ArgumentException">'input.Length' == 0. </exception>
        /// <exception cref="ObjectDisposedException">If <see cref="AsymmetricSignatureProvider.Dispose(bool)"/> has been called. </exception>
        /// <exception cref="InvalidOperationException">If the internal <see cref="AsymmetricSignatureProvider"/> is null. This can occur if the constructor parameter 'willBeUsedforSigning' was not 'true'.</exception>
        /// <exception cref="InvalidOperationException">If the internal <see cref="HashAlgorithm"/> is null. This can occur if a derived type deletes it or does not create it.</exception>
        public override byte[] Sign(byte[] input)
        {
            if (input == null || input.Length == 0)
                throw LogHelper.LogArgumentNullException("input");

            if (_disposed)
                throw LogHelper.LogExceptionMessage(new ObjectDisposedException(GetType().ToString()));

#if NETSTANDARD1_4
            if (_rsa != null)
                return _rsa.SignData(input, _hashAlgorithmName, RSASignaturePadding.Pkcs1);
            else if (_ecdsa != null)
                return _ecdsa.SignData(input, _hashAlgorithmName);

            throw LogHelper.LogExceptionMessage(new InvalidOperationException(LogHelper.FormatInvariant(LogMessages.IDX10644, _hashAlgorithmName)));
#endif

#if NET46
            if (_rsa != null)
                return _rsa.SignData(input, _hashAlgorithmName, RSASignaturePadding.Pkcs1);
#endif

#if NET45 || NET451 || NET46
            if (_rsaCryptoServiceProviderProxy != null)
                return _rsaCryptoServiceProviderProxy.SignData(input, _hashAlgorithmString);
            else if (_ecdsa != null)
                return _ecdsa.SignData(input);

            throw LogHelper.LogExceptionMessage(new InvalidOperationException(LogHelper.FormatInvariant(LogMessages.IDX10644, _hashAlgorithmString)));
#endif           
        }

        /// <summary>
        /// Verifies that a signature over the' input' matches the signature.
        /// </summary>
        /// <param name="input">The bytes to generate the signature over.</param>
        /// <param name="signature">The value to verify against.</param>
        /// <returns>true if signature matches, false otherwise.</returns>
        /// <exception cref="ArgumentNullException">'input' is null.</exception>
        /// <exception cref="ArgumentNullException">'signature' is null.</exception>
        /// <exception cref="ArgumentException">'input.Length' == 0.</exception>
        /// <exception cref="ArgumentException">'signature.Length' == 0.</exception>
        /// <exception cref="ObjectDisposedException">If <see cref="AsymmetricSignatureProvider.Dispose(bool)"/> has been called. </exception>
        /// <exception cref="InvalidOperationException">If the internal <see cref="AsymmetricSignatureProvider"/> is null. This can occur if a derived type does not call the base constructor.</exception>
        /// <exception cref="InvalidOperationException">If the internal <see cref="HashAlgorithm"/> is null. This can occur if a derived type deletes it or does not create it.</exception>
        public override bool Verify(byte[] input, byte[] signature)
        {
            if (input == null || input.Length == 0)
                throw LogHelper.LogArgumentNullException("input");

            if (signature == null || signature.Length == 0)
                throw LogHelper.LogArgumentNullException("signature");

            if (_disposed)
                throw LogHelper.LogExceptionMessage(new ObjectDisposedException(GetType().ToString()));

#if NETSTANDARD1_4
            if (_rsa != null)
                return _rsa.VerifyData(input, signature, _hashAlgorithmName, RSASignaturePadding.Pkcs1);
            else if (_ecdsa != null)
                return _ecdsa.VerifyData(input, signature, _hashAlgorithmName);
#endif

#if NET45 || NET451 || NET46
            if (_rsaCryptoServiceProviderProxy != null)
                return _rsaCryptoServiceProviderProxy.VerifyData(input, _hashAlgorithmString, signature);
            else if (_ecdsa != null)
                return _ecdsa.VerifyData(input, signature);
#endif

#if NET46
            if (_rsa != null)
                return _rsa.VerifyData(input, signature, _hashAlgorithmName, RSASignaturePadding.Pkcs1);
#endif

            throw LogHelper.LogExceptionMessage(new InvalidOperationException(LogMessages.IDX10644));
        }

        /// <summary>
        /// Validates that the asymmetric key size is more than the allowed minimum
        /// </summary>
        /// <param name="key">The asymmetric key to validate</param>
        /// <param name="algorithm">Algorithm for which this key will be used</param>
        /// <param name="willCreateSignatures">Whether they key will be used for creating signatures</param>
        public virtual void ValidateAsymmetricSecurityKeySize(SecurityKey key, string algorithm, bool willCreateSignatures)
        {
            if (willCreateSignatures)
            {
                if (MinimumAsymmetricKeySizeInBitsForSigningMap.ContainsKey(algorithm) && key.KeySize < MinimumAsymmetricKeySizeInBitsForSigningMap[algorithm])
                    throw LogHelper.LogExceptionMessage(new ArgumentOutOfRangeException("key.KeySize", LogHelper.FormatInvariant(LogMessages.IDX10630, key, MinimumAsymmetricKeySizeInBitsForSigningMap[algorithm], key.KeySize)));
            }

            if (MinimumAsymmetricKeySizeInBitsForVerifyingMap.ContainsKey(algorithm) && key.KeySize < MinimumAsymmetricKeySizeInBitsForVerifyingMap[algorithm])
                throw LogHelper.LogExceptionMessage(new ArgumentOutOfRangeException("key.KeySize", LogHelper.FormatInvariant(LogMessages.IDX10631, key, MinimumAsymmetricKeySizeInBitsForVerifyingMap[algorithm], key.KeySize)));
        }

        /// <summary>
        /// Calls <see cref="HashAlgorithm.Dispose()"/> to release this managed resources.
        /// </summary>
        /// <param name="disposing">true, if called from Dispose(), false, if invoked inside a finalizer.</param>
        protected override void Dispose(bool disposing)
        {
            if (!_disposed)
            {
                _disposed = true;

                if (disposing)
                {
#if NETSTANDARD1_4 || NET46
                    if (_rsa != null && _disposeRsa)
                        _rsa.Dispose();
#endif

#if NET45 || NET451 || NET46
                    if (_rsaCryptoServiceProviderProxy != null)
                        _rsaCryptoServiceProviderProxy.Dispose();
#endif
                    if (_ecdsa != null && _disposeEcdsa)
                        _ecdsa.Dispose();
                }
            }
        }
    }
}
