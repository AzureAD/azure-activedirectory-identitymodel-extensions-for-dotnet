// Copyright (c) Microsoft Corporation. All rights reserved.
// Licensed under the MIT License.

using System.Security.Cryptography;

namespace Microsoft.IdentityModel.Tokens
{
    /// <summary>
    /// Represents a security algorithm is used for MLDSA.
    /// AsymmetricAdapter will need to be expanded so we will have a pool of these types.
    /// </summary>
#pragma warning disable RS0016 // Add public types and members to the declared API
    public abstract class Mldsa : AsymmetricAlgorithm
    {
        private bool _disposed;
        private string _thumbprint;

        /// <summary>
        /// Instantiates a <see cref="Mldsa"/> AsymmetricAlgorithm that can Validate using ML-DSA.
        /// </summary>
        protected Mldsa()
        {
            PublicKey = string.Empty;
            PrivateKey = string.Empty;
            Kid = string.Empty;
        }

        /// <summary>
        /// Creates a random <see cref="AsymmetricAlgorithm"/> that supports ML-DSA.
        /// </summary>
        /// <param name="keyType"></param>
        /// <returns>A <see cref="Mldsa"/> that cam be used for signing and verifying.</returns>
        public new static Mldsa Create(string keyType)
        {
            return MldsaWin.Create(keyType);
        }

        /// <summary>
        /// Instantiates a <see cref="Mldsa"/> AsymmetricAlgorithm that can Validate using ML-DSA.
        /// </summary>
        /// <param name="publicKey">The public key in base64 format.</param>
        /// <param name="algorithm">The algorithm that defines the public key.</param>
        public static Mldsa Create(string publicKey, string algorithm)
        {
            // Needs logic to determine the OS, follow the pattern of .net
            return new MldsaWin(publicKey, algorithm);
        }

        /// <summary>
        /// Signs a byte array using ML-DSA
        /// </summary>
        /// <param name="data">The data to sign.</param>
        /// <param name="signature">The Signature.</param>
        /// <remarks>This is an inefficient model, as we should not be allocating here.
        /// Eventually we will follow the model of using the ArrayPool for allocations.</remarks>
        public abstract void SignData(byte[] data, out byte[] signature);

        /// <summary>
        /// Verifies a signature using ML-DSA
        /// </summary>
        /// <param name="data">The data that was signed.</param>
        /// <param name="signature">The signature that should match.</param>
        /// <returns></returns>
        public abstract bool VerifyData(byte[] data, byte[] signature);

        /// <summary>
        /// The algorithm that defines the public key.
        /// </summary>
        public string Algorithm { get; protected set; }

        /// <summary>
        /// The length in bytes of the signature.
        /// </summary>
        public int SignatureSize { get; protected set; }

        /// <summary>
        /// The public key in Base64 format.
        /// </summary>
        public string PublicKey { get; protected set; }

        /// <summary>
        /// The private key in Base64 format.
        /// </summary>
        public string PrivateKey { get; protected set; }

        /// <summary>
        /// The key identifier.
        /// </summary>
        public string Kid { get; protected set; }

        /// <summary>
        /// The thumbprint of the key. Following this spec: https://datatracker.ietf.org/doc/draft-ietf-cose-dilithium/ section 6.
        /// </summary>
        public string Thumbprint
        {
            get
            {
                if (string.IsNullOrEmpty(_thumbprint))
                {
                    using (SHA256 sha = SHA256.Create())
                    {
                        byte[] hash = sha.ComputeHash(Base64UrlEncoder.DecodeBytes(PublicKey));
                        _thumbprint = Base64UrlEncoder.Encode(hash);
                    }
                }

                return _thumbprint;
            }
        }

        /// <summary>
        /// Releases the resources used by the current instance.
        /// </summary>
        /// <param name="disposing">If true, release both managed and unmanaged resources; otherwise, release only unmanaged resources.</param>
        protected override void Dispose(bool disposing)
        {
            if (!_disposed)
            {
                _disposed = true;
                base.Dispose(disposing);
            }
        }
    }
#pragma warning restore RS0016 // Add public types and members to the declared API
}

