// Copyright (c) Microsoft Corporation. All rights reserved.
// Licensed under the MIT License.

using System;
using System.Text;

namespace Microsoft.IdentityModel.Tokens
{
#pragma warning disable RS0016 // Add public types and members to the declared API

    /// <summary>
    /// Represents a security key that is used for MLDSA. Similar to RsaSecurityKey.
    /// Eventually the plan is for this to derive from AsymmetricSecurityKey.
    /// AsymmetricAdapter will need to be expanded so we will have a pool of these types.
    /// </summary>
    public class MldsaSecurityKey : AsymmetricSecurityKey
    {
        private Mldsa _mldsa;
        private byte[] _jwkThumbprint;

        /// <summary>
        /// Initializes a new instance of the <see cref="MldsaSecurityKey"/> class.
        /// </summary>
        /// <param name="mldsa"><see cref="Mldsa"/></param>
        public MldsaSecurityKey(Mldsa mldsa)
        {
            if (mldsa == null)
                throw new ArgumentNullException(nameof(mldsa));

            _mldsa = mldsa;
        }

        /// <inheritdoc/>
        public override bool CanComputeJwkThumbprint() => true;

        /// <inheritdoc/>
        public override byte[] ComputeJwkThumbprint()
        {
            _jwkThumbprint ??= Encoding.UTF8.GetBytes(_mldsa.Thumbprint);

            return _jwkThumbprint;
        }

        /// <summary>
        /// Signs a byte array using ML-DSA
        /// </summary>
        /// <param name="data">The data to sign.</param>
        /// <param name="signature">The Signature.</param>
        /// <remarks>This is an inefficient model, as we should not be allocating here.
        /// Eventually we will follow the model of using the ArrayPool for allocations.</remarks>
        public void SignData(byte[] data, out byte[] signature)
        {
            if (data == null)
                throw new ArgumentNullException(nameof(data));

            _mldsa.SignData(data, out signature);
        }

        /// <summary>
        /// Verifies a signature using ML-DSA
        /// </summary>
        /// <param name="data">The data that was signed.</param>
        /// <param name="signature">The signature that should match.</param>
        /// <returns></returns>
        public bool VerifyData(byte[] data, byte[] signature)
        {
            if (data == null)
                throw new ArgumentNullException(nameof(data));

            if (signature == null)
                throw new ArgumentNullException(nameof(signature));

            return _mldsa.VerifyData(data, signature);
        }

        /// <summary>
        /// The algorithm that defines the public key.
        /// </summary>
        public string Algorithm => _mldsa.Algorithm;

        /// <summary>
        /// The length of the signature.
        /// </summary>
        private int SignatureSize => _mldsa.SignatureSize;

        /// <summary>
        /// The public key in Base64 format.
        /// </summary>
        public string PublicKey => _mldsa.PublicKey;

        /// <summary>
        /// The private key in Base64 format.
        /// </summary>
        public string PrivateKey => _mldsa.PrivateKey;

        /// <summary>
        /// The key identifier.
        /// </summary>
        public string Kid => _mldsa.Thumbprint;

        /// <summary>
        /// The key identifier.
        /// </summary>
        public override string KeyId => _mldsa.Thumbprint;

        /// <summary>
        /// The MLDSA object that performs the signing and verification.
        /// </summary>
        public Mldsa Mldsa => _mldsa;

        /// <summary>
        /// The thumbprint of the key. Following this spec: https://datatracker.ietf.org/doc/draft-ietf-cose-dilithium/ section 6.
        /// </summary>
        public string Thumbprint => _mldsa.Thumbprint;

        /// <inheritdoc/>
        [Obsolete("HasPrivateKey method is deprecated, please use PrivateKeyStatus instead.")]
        public override bool HasPrivateKey
        {
            get => false;
        }

        /// <inheritdoc/>
        public override PrivateKeyStatus PrivateKeyStatus
        {
            get => PrivateKeyStatus.Unknown;
        }

        /// <inheritdoc/>
        public override int KeySize => _mldsa.KeySize;
    }
#pragma warning restore RS0016 // Add public types and members to the declared API
}

