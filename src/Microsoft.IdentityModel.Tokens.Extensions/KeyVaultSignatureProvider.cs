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
using System.Threading;
using System.Threading.Tasks;
using Microsoft.Azure.KeyVault;
using Microsoft.IdentityModel.Logging;

namespace Microsoft.IdentityModel.Tokens.Extensions
{
    /// <summary>
    /// Provides signing and verifying operations using Azure Key Vault.
    /// </summary>
    public class KeyVaultSignatureProvider : SignatureProvider
    {
        private readonly HashAlgorithm _hash;
        private readonly IKeyVaultClient _client;
        private readonly KeyVaultSecurityKey _key;
        private bool _disposed = false;

        /// <summary>
        /// Initializes a new instance of the <see cref="KeyVaultSignatureProvider"/> class.
        /// </summary>
        /// <param name="key">The <see cref="SecurityKey"/> that will be used for signature operations.</param>
        /// <param name="algorithm">The signature algorithm to apply.</param>
        /// <param name="willCreateSignatures">Whether this <see cref="KeyVaultSignatureProvider"/> is required to create signatures then set this to true.</param>
        public KeyVaultSignatureProvider(SecurityKey key, string algorithm, bool willCreateSignatures)
            : this(key, algorithm, willCreateSignatures, null)
        {
        }

        /// <summary>
        /// Initializes a new instance of the <see cref="KeyVaultSignatureProvider"/> class.
        /// </summary>
        /// <param name="key">The <see cref="SecurityKey"/> that will be used for signature operations.</param>
        /// <param name="algorithm">The signature algorithm to apply.</param>
        /// <param name="willCreateSignatures">Whether this <see cref="KeyVaultSignatureProvider"/> is required to create signatures then set this to true.</param>
        /// <param name="client">A mock <see cref="IKeyVaultClient"/> used for testing purposes.</param>
        internal KeyVaultSignatureProvider(SecurityKey key, string algorithm, bool willCreateSignatures, IKeyVaultClient client)
            : base(key, algorithm)
        {
            _key = key as KeyVaultSecurityKey ?? throw LogHelper.LogArgumentNullException(nameof(key));
            _client = client ?? new KeyVaultClient(new KeyVaultClient.AuthenticationCallback(_key.Callback));
            WillCreateSignatures = willCreateSignatures;

            switch (algorithm)
            {
                case SecurityAlgorithms.RsaSha256:
                    _hash = SHA256.Create();
                    break;
                case SecurityAlgorithms.RsaSha384:
                    _hash = SHA384.Create();
                    break;
                case SecurityAlgorithms.RsaSha512:
                    _hash = SHA512.Create();
                    break;
                default:
                    throw LogHelper.LogExceptionMessage(new ArgumentException(LogHelper.FormatInvariant(LogMessages.IDX10652, algorithm), nameof(algorithm)));
            }
        }

        /// <summary>
        /// Produces a signature over the 'input' using Azure Key Vault.
        /// </summary>
        /// <param name="input">bytes to sign.</param>
        /// <returns>signed bytes</returns>
        public override byte[] Sign(byte[] input)
        {
            return SignAsync(input, CancellationToken.None).ConfigureAwait(false).GetAwaiter().GetResult();
        }

        /// <summary>
        /// Verifies that signature created over the 'input' using Azure Key Vault.
        /// </summary>
        /// <param name="input">bytes to verify.</param>
        /// <param name="signature">signature to compare against.</param>
        /// <returns>true if the computed signature matches the signature parameter, false otherwise.</returns>
        public override bool Verify(byte[] input, byte[] signature)
        {
            return VerifyAsync(input, signature, CancellationToken.None).ConfigureAwait(false).GetAwaiter().GetResult();
        }

        /// <summary>
        /// Performs application-defined tasks associated with freeing, releasing, or resetting unmanaged resources.
        /// </summary>
        /// <param name="disposing">true, if called from Dispose(), false, if invoked inside a finalizer</param>
        protected override void Dispose(bool disposing)
        {
            if (!_disposed)
            {
                if (disposing)
                {
                    _disposed = true;
                    _client.Dispose();
                }
            }
        }

        /// <summary>
        /// Creates a digital signature using Azure Key Vault.
        /// </summary>
        /// <param name="input">bytes to sign.</param>
        /// <param name="cancellation">Propagates notification that operations should be canceled.</param>
        /// <returns>signed bytes</returns>
        private async Task<byte[]> SignAsync(byte[] input, CancellationToken cancellation)
        {
            return (await _client.SignAsync(_key.KeyId, Algorithm, _hash.ComputeHash(input), cancellation)).Result;
        }

        /// <summary>
        /// Verifies a digital signature using Azure Key Vault.
        /// </summary>
        /// <param name="input">bytes to verify.</param>
        /// <param name="signature">signature to compare against.</param>
        /// <param name="cancellation">Propagates notification that operations should be canceled.</param>
        /// <returns>true if the computed signature matches the signature parameter, false otherwise.</returns>
        private async Task<bool> VerifyAsync(byte[] input, byte[] signature, CancellationToken cancellation)
        {
            return await _client.VerifyAsync(_key.KeyId, Algorithm, _hash.ComputeHash(input), signature, cancellation);
        }
    }
}
