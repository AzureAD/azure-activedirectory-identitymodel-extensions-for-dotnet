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
    /// Provides signature and verification operations for Asymmetric Algorithms using a <see cref="SecurityKey"/>.
    /// </summary>
    public class AsymmetricSignatureProvider : SignatureProvider
    {
        private bool _disposed;
        private AsymmetricAdapter _asymmetricAdapter;
        private CryptoProviderFactory _cryptoProviderFactory;
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
            { SecurityAlgorithms.RsaSha512Signature, 2048 },
            { SecurityAlgorithms.RsaSsaPssSha256, 528 },
            { SecurityAlgorithms.RsaSsaPssSha384, 784 },
            { SecurityAlgorithms.RsaSsaPssSha512, 1040 },
            { SecurityAlgorithms.RsaSsaPssSha256Signature, 528 },
            { SecurityAlgorithms.RsaSsaPssSha384Signature, 784 },
            { SecurityAlgorithms.RsaSsaPssSha512Signature, 1040 }
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
            { SecurityAlgorithms.RsaSha512Signature, 1024 },
            { SecurityAlgorithms.RsaSsaPssSha256, 528 },
            { SecurityAlgorithms.RsaSsaPssSha384, 784 },
            { SecurityAlgorithms.RsaSsaPssSha512, 1040 },
            { SecurityAlgorithms.RsaSsaPssSha256Signature, 528 },
            { SecurityAlgorithms.RsaSsaPssSha384Signature, 784 },
            { SecurityAlgorithms.RsaSsaPssSha512Signature, 1040 }
        };

        internal AsymmetricSignatureProvider(SecurityKey key, string algorithm, CryptoProviderFactory cryptoProviderFactory)
            : this(key, algorithm)
        {
            _cryptoProviderFactory = cryptoProviderFactory;
        }

        internal AsymmetricSignatureProvider(SecurityKey key, string algorithm, bool willCreateSignatures, CryptoProviderFactory cryptoProviderFactory)
            : this(key, algorithm, willCreateSignatures)
        {
            _cryptoProviderFactory = cryptoProviderFactory;
        }

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
        /// <param name="willCreateSignatures">If this <see cref="AsymmetricSignatureProvider"/> is required to create signatures then set this to true.</param>
        /// <para>
        /// Creating signatures requires that the <see cref="SecurityKey"/> has access to a private key.
        /// Verifying signatures (the default), does not require access to the private key.
        /// </para>
        /// <exception cref="ArgumentNullException"><paramref name="key"/>is null.</exception>
        /// <exception cref="ArgumentNullException"><paramref name="algorithm"/>is null or empty.</exception>
        /// <exception cref="InvalidOperationException"><paramref name="willCreateSignatures"/>is true and there is no private key.</exception>
        /// <exception cref="NotSupportedException">If <see cref="SecurityKey"/> and algorithm pair are not supported.</exception>
        /// <exception cref="ArgumentOutOfRangeException">
        /// willCreateSignatures is true and <see cref="SecurityKey"/>.KeySize is less than the size corresponding to the given algorithm in <see cref="AsymmetricSignatureProvider.MinimumAsymmetricKeySizeInBitsForSigningMap"/>.
        /// </exception>
        /// <exception cref="ArgumentOutOfRangeException">
        /// <see cref="SecurityKey"/>.KeySize is less than the size corresponding to the algorithm in <see cref="AsymmetricSignatureProvider.MinimumAsymmetricKeySizeInBitsForVerifyingMap"/>. Note: this is always checked.
        /// </exception>
        /// <exception cref="InvalidOperationException">If the runtime is unable to create a suitable cryptographic provider.</exception>
        public AsymmetricSignatureProvider(SecurityKey key, string algorithm, bool willCreateSignatures)
            : base(key, algorithm)
        {
            _cryptoProviderFactory = key.CryptoProviderFactory;
            _minimumAsymmetricKeySizeInBitsForSigningMap = new Dictionary<string, int>(DefaultMinimumAsymmetricKeySizeInBitsForSigningMap);
            _minimumAsymmetricKeySizeInBitsForVerifyingMap = new Dictionary<string, int>(DefaultMinimumAsymmetricKeySizeInBitsForVerifyingMap);

            var jsonWebKey = key as JsonWebKey;
            if (jsonWebKey != null)
                JsonWebKeyConverter.TryConvertToSecurityKey(jsonWebKey, out SecurityKey _);

            if (willCreateSignatures && FoundPrivateKey(key) == PrivateKeyStatus.DoesNotExist)
                throw LogHelper.LogExceptionMessage(new InvalidOperationException(LogHelper.FormatInvariant(LogMessages.IDX10638, key)));

            if (!_cryptoProviderFactory.IsSupportedAlgorithm(algorithm, key))
                throw LogHelper.LogExceptionMessage(new NotSupportedException(LogHelper.FormatInvariant(LogMessages.IDX10634, (algorithm ?? "null"), key)));

            ValidateAsymmetricSecurityKeySize(key, algorithm, willCreateSignatures);
            _asymmetricAdapter = ResolveAsymmetricAdapter(jsonWebKey?.ConvertedSecurityKey ?? key, algorithm, willCreateSignatures);
            WillCreateSignatures = willCreateSignatures;
        }

        /// <summary>
        /// Gets the mapping from algorithm to the minimum <see cref="AsymmetricSecurityKey"/>.KeySize for creating signatures.
        /// </summary>
        public IReadOnlyDictionary<string, int> MinimumAsymmetricKeySizeInBitsForSigningMap
        {
            get => _minimumAsymmetricKeySizeInBitsForSigningMap;
        }

        /// <summary>
        /// Gets the mapping from algorithm to the minimum <see cref="AsymmetricSecurityKey"/>.KeySize for verifying signatures.
        /// </summary>
        public IReadOnlyDictionary<string, int> MinimumAsymmetricKeySizeInBitsForVerifyingMap
        {
            get => _minimumAsymmetricKeySizeInBitsForVerifyingMap;
        }

        private PrivateKeyStatus FoundPrivateKey(SecurityKey key)
        {
            if (key is AsymmetricSecurityKey asymmetricSecurityKey)
                return asymmetricSecurityKey.PrivateKeyStatus;

            if (key is JsonWebKey jsonWebKey)
                return jsonWebKey.HasPrivateKey ? PrivateKeyStatus.Exists : PrivateKeyStatus.DoesNotExist;

            return PrivateKeyStatus.Unknown;
        }

#if NET461 || NETSTANDARD2_0
        /// <summary>
        /// Creating a Signature requires the use of a <see cref="HashAlgorithm"/>.
        /// This method returns the <see cref="HashAlgorithmName"/>
        /// that describes the <see cref="HashAlgorithm"/>to use when generating a Signature.
        /// </summary>
        /// <param name="algorithm">The SignatureAlgorithm in use.</param>
        /// <returns>The <see cref="HashAlgorithmName"/> to use.</returns>
        /// <exception cref="ArgumentNullException">if <paramref name="algorithm"/> is null or whitespace.</exception>
        /// <exception cref="ArgumentOutOfRangeException">if <paramref name="algorithm"/> is not supported.</exception>
        protected virtual HashAlgorithmName GetHashAlgorithmName(string algorithm)
        {
            if (string.IsNullOrWhiteSpace(algorithm))
                throw LogHelper.LogArgumentNullException(nameof(algorithm));

            switch (algorithm)
            {
                case SecurityAlgorithms.EcdsaSha256:
                case SecurityAlgorithms.EcdsaSha256Signature:
                case SecurityAlgorithms.RsaSha256:
                case SecurityAlgorithms.RsaSha256Signature:
                case SecurityAlgorithms.RsaSsaPssSha256:
                case SecurityAlgorithms.RsaSsaPssSha256Signature:
                    return HashAlgorithmName.SHA256;

                case SecurityAlgorithms.EcdsaSha384:
                case SecurityAlgorithms.EcdsaSha384Signature:
                case SecurityAlgorithms.RsaSha384:
                case SecurityAlgorithms.RsaSha384Signature:
                case SecurityAlgorithms.RsaSsaPssSha384:
                case SecurityAlgorithms.RsaSsaPssSha384Signature:
                    return HashAlgorithmName.SHA384;

                case SecurityAlgorithms.EcdsaSha512:
                case SecurityAlgorithms.EcdsaSha512Signature:
                case SecurityAlgorithms.RsaSha512:
                case SecurityAlgorithms.RsaSha512Signature:
                case SecurityAlgorithms.RsaSsaPssSha512:
                case SecurityAlgorithms.RsaSsaPssSha512Signature:
                    return HashAlgorithmName.SHA512;
            }

            throw LogHelper.LogExceptionMessage(new ArgumentOutOfRangeException(nameof(algorithm), LogHelper.FormatInvariant(LogMessages.IDX10652, algorithm)));
        }

        private AsymmetricAdapter ResolveAsymmetricAdapter(SecurityKey key, string algorithm, bool requirePrivateKey)
        {
            var hashAlgoritmName = GetHashAlgorithmName(algorithm);
            return new AsymmetricAdapter(key, algorithm, _cryptoProviderFactory.CreateHashAlgorithm(hashAlgoritmName), hashAlgoritmName, requirePrivateKey);
        }
#endif

#if NET45
        /// <summary>
        /// Creating a Signature requires the use of a <see cref="HashAlgorithm"/>.
        /// This method returns the type of the HashAlgorithm (as a string)
        /// that describes the <see cref="HashAlgorithm"/>to use when generating a Signature.
        /// </summary>
        /// <param name="algorithm">The SignatureAlgorithm in use.</param>
        /// <exception cref="ArgumentNullException">if <paramref name="algorithm"/>is null or whitespace.</exception>
        /// <exception cref="ArgumentException">if <paramref name="algorithm"/> is not supported.</exception>
        protected virtual string GetHashAlgorithmString(string algorithm)
        {
            if (string.IsNullOrWhiteSpace(algorithm))
                throw LogHelper.LogArgumentNullException(nameof(algorithm));

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

        /// <summary>
        /// This method is here, just to keep the #if out of the constructor.
        /// </summary>
        /// <param name="key"></param>
        /// <param name="algorithm"></param>
        /// <param name="requirePrivateKey"></param>
        /// <returns></returns>
        private AsymmetricAdapter ResolveAsymmetricAdapter(SecurityKey key, string algorithm, bool requirePrivateKey)
        {
            return new AsymmetricAdapter(key, algorithm, _cryptoProviderFactory.CreateHashAlgorithm(GetHashAlgorithmString(algorithm)), requirePrivateKey);
        }
#endif

        /// <summary>
        /// Produces a signature over the 'input' using the <see cref="AsymmetricSecurityKey"/> and algorithm passed to <see cref="AsymmetricSignatureProvider( SecurityKey, string, bool )"/>.
        /// </summary>
        /// <param name="input">The bytes to be signed.</param>
        /// <returns>A signature over the input.</returns>
        /// <exception cref="ArgumentNullException">if <paramref name="input"/> is null.</exception>
        /// <exception cref="ArgumentNullException">if <paramref name="input"/>.Length == 0.</exception>
        /// <exception cref="ObjectDisposedException">If <see cref="AsymmetricSignatureProvider.Dispose(bool)"/> has been called. </exception>
        /// <remarks>Sign is thread safe.</remarks>
        public override byte[] Sign(byte[] input)
        {
            if (input == null || input.Length == 0)
                throw LogHelper.LogArgumentNullException(nameof(input));

            if (_disposed)
            {
                CryptoProviderCache?.TryRemove(this);
                throw LogHelper.LogExceptionMessage(new ObjectDisposedException(GetType().ToString()));
            }

            try
            {
                return _asymmetricAdapter.Sign(input);
            }
            catch
            {
                CryptoProviderCache?.TryRemove(this);
                throw;
            }
        }

        /// <summary>
        /// Validates that an asymmetric key size is of sufficient size for a SignatureAlgorithm.
        /// </summary>
        /// <param name="key">The asymmetric key to validate.</param>
        /// <param name="algorithm">Algorithm for which this key will be used.</param>
        /// <param name="willCreateSignatures">Whether they key will be used for creating signatures.</param>
        /// <exception cref="ArgumentNullException">if <paramref name="key"/>is null.</exception>
        /// <exception cref="ArgumentNullException">if <paramref name="algorithm"/>is null or empty.</exception>
        /// <exception cref="ArgumentOutOfRangeException">if <paramref name="key"/>.KeySize is less than the minimum
        /// acceptable size.</exception>
        /// <remarks>
        /// <seealso cref="MinimumAsymmetricKeySizeInBitsForSigningMap"/> for minimum signing sizes.
        /// <seealso cref="MinimumAsymmetricKeySizeInBitsForVerifyingMap"/> for minimum verifying sizes.
        /// </remarks>
        public virtual void ValidateAsymmetricSecurityKeySize(SecurityKey key, string algorithm, bool willCreateSignatures)
        {
            if (key == null)
                throw LogHelper.LogArgumentNullException(nameof(key));

            if (string.IsNullOrEmpty(algorithm))
                throw LogHelper.LogArgumentNullException(nameof(algorithm));

            int keySize = key.KeySize;
            if (key is AsymmetricSecurityKey securityKey)
            {
                keySize = securityKey.KeySize;
            }
            else if (key is JsonWebKey jsonWebKey)
            {
                JsonWebKeyConverter.TryConvertToSecurityKey(jsonWebKey, out SecurityKey convertedSecurityKey);
                if (convertedSecurityKey is AsymmetricSecurityKey convertedAsymmetricKey)
                    keySize = convertedAsymmetricKey.KeySize;
                else if (convertedSecurityKey is SymmetricSecurityKey)
                    throw LogHelper.LogExceptionMessage(new NotSupportedException(LogHelper.FormatInvariant(LogMessages.IDX10704, key)));
            }
            else
            {
                throw LogHelper.LogExceptionMessage(new NotSupportedException(LogHelper.FormatInvariant(LogMessages.IDX10704, key)));
            }

            if (willCreateSignatures)
            {
                if (MinimumAsymmetricKeySizeInBitsForSigningMap.ContainsKey(algorithm)
                && keySize < MinimumAsymmetricKeySizeInBitsForSigningMap[algorithm])
                    throw LogHelper.LogExceptionMessage(new ArgumentOutOfRangeException("key.KeySize", LogHelper.FormatInvariant(LogMessages.IDX10630, key, MinimumAsymmetricKeySizeInBitsForSigningMap[algorithm], keySize)));
            }
            else if (MinimumAsymmetricKeySizeInBitsForVerifyingMap.ContainsKey(algorithm)
                 && keySize < MinimumAsymmetricKeySizeInBitsForVerifyingMap[algorithm])
            {
                throw LogHelper.LogExceptionMessage(new ArgumentOutOfRangeException("key.KeySize", LogHelper.FormatInvariant(LogMessages.IDX10631, key, MinimumAsymmetricKeySizeInBitsForVerifyingMap[algorithm], keySize)));
            }
        }

        /// <summary>
        /// Verifies that the <paramref name="signature"/> over <paramref name="input"/> using the
        /// <see cref="SecurityKey"/> and <see cref="SignatureProvider.Algorithm"/> specified by this
        /// <see cref="SignatureProvider"/> are consistent.
        /// </summary>
        /// <param name="input">The bytes to generate the signature over.</param>
        /// <param name="signature">The value to verify against.</param>
        /// <returns>true if signature matches, false otherwise.</returns>
        /// <exception cref="ArgumentNullException"><paramref name="input"/> is null or has length == 0.</exception>
        /// <exception cref="ArgumentNullException"><paramref name="signature"/> is null or has length == 0.</exception>
        /// <exception cref="ObjectDisposedException">If <see cref="AsymmetricSignatureProvider.Dispose(bool)"/> has been called. </exception>
        /// <remarks>Verify is thread safe.</remarks>
        public override bool Verify(byte[] input, byte[] signature)
        {
            if (input == null || input.Length == 0)
                throw LogHelper.LogArgumentNullException(nameof(input));

            if (signature == null || signature.Length == 0)
                throw LogHelper.LogArgumentNullException(nameof(signature));

            if (_disposed)
            {
                CryptoProviderCache?.TryRemove(this);
                throw LogHelper.LogExceptionMessage(new ObjectDisposedException(GetType().ToString()));
            }

            try
            {
                return _asymmetricAdapter.Verify(input, signature);
            }
            catch
            {
                CryptoProviderCache?.TryRemove(this);
                throw;
            }
        }

        /// <summary>
        /// Calls to release managed resources.
        /// </summary>
        /// <param name="disposing">true, if called from Dispose(), false, if invoked inside a finalizer.</param>
        protected override void Dispose(bool disposing)
        {
            if (!_disposed)
            {
                _disposed = true;

                if (disposing)
                {
                    CryptoProviderCache?.TryRemove(this);
                    _asymmetricAdapter.Dispose();
                }
            }
        }
    }
}
