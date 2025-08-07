// Copyright (c) Microsoft Corporation. All rights reserved.
// Licensed under the MIT License.

using System;
using System.Security.Cryptography;

namespace Microsoft.IdentityModel.Tokens
{
    /// <summary>
    /// Represents a security algorithm is used for MLDSA on Windows.
    /// AsymmetricAdapter will need to be expanded so we will have a pool of these types.
    /// </summary>
#pragma warning disable RS0016 // Add public types and members to the declared API
    public class MldsaArm : Mldsa
    {
        private bool _disposed;

        internal MldsaArm() : base()
        {
            Handle = IntPtr.Zero;
        }

        /// <summary>
        /// Creates a random <see cref="AsymmetricAlgorithm"/> that supports ML-DSA.
        /// </summary>
        /// <param name="keyType"></param>
        /// <returns>A <see cref="Mldsa"/> that cam be used for signing and verifying.</returns>
        internal new static Mldsa Create(string keyType)
        {
            if (!string.Equals(SecurityAlgorithms.Mldsa44, keyType, StringComparison.Ordinal))
                throw new NotSupportedException($"{typeof(MldsaSecurityKey).FullName} only supports: '{SecurityAlgorithms.Mldsa44}'.");

            MldsaArm mldsa = new MldsaArm();
            mldsa.Algorithm = keyType;

            SYMCRYPT_MLDSA_PARAMS_ENUM mldsaKeyType = SYMCRYPT_MLDSA_PARAMS_ENUM.MLDSA44;

            // Initialize the key structure
            mldsa.Handle = SymCrypt.SymCryptMlDsakeyAllocate(mldsaKeyType);

            // Generate the key
            int error = SymCrypt.SymCryptMlDsakeyGenerate(mldsa.Handle, 0);
            long sizeOfKey = 0;

            error = SymCrypt.SymCryptMlDsaSizeofKeyFormatFromParams(
                mldsaKeyType,
                SYMCRYPT_MLDSAKEY_FORMAT.PRIVATE_KEY,
                ref sizeOfKey);

            byte[] keyFormat = new byte[sizeOfKey];
            error = SymCrypt.SymCryptMlDsakeyGetValue(
                mldsa.Handle,
                keyFormat,
                sizeOfKey,
                SYMCRYPT_MLDSAKEY_FORMAT.PRIVATE_KEY,
                0);

            mldsa.PrivateKey = Convert.ToBase64String(keyFormat);

            error = SymCrypt.SymCryptMlDsaSizeofKeyFormatFromParams(
                mldsaKeyType,
                SYMCRYPT_MLDSAKEY_FORMAT.PUBLIC_KEY,
                ref sizeOfKey);

            error = SymCrypt.SymCryptMlDsakeyGetValue(
                mldsa.Handle,
                keyFormat,
                sizeOfKey,
                SYMCRYPT_MLDSAKEY_FORMAT.PUBLIC_KEY,
                0);

            mldsa.PublicKey = Base64UrlEncoder.Encode(keyFormat, 0, (int)sizeOfKey);

            int signatureSize = 0;
            error = SymCrypt.SymCryptMlDsaSizeofSignatureFromParams(mldsaKeyType, ref signatureSize);

            mldsa.SignatureSize = signatureSize;

            return mldsa;
        }


        /// <summary>
        /// Instantiates a <see cref="Mldsa"/> AsymmetricAlgorithm that can Validate using ML-DSA.
        /// </summary>
        /// <param name="publicKey">The public key in base64 format.</param>
        /// <param name="algorithm">The algorithm that defines the public key.</param>
        internal MldsaArm(string publicKey, string algorithm)
        {
            if (string.IsNullOrEmpty(publicKey))
                throw new ArgumentNullException(nameof(publicKey));

            if (string.IsNullOrEmpty(algorithm))
                throw new ArgumentNullException(nameof(algorithm));

            if (algorithm != SecurityAlgorithms.Mldsa44)
                throw new NotSupportedException($"{typeof(MldsaSecurityKey).FullName} only supports: '{SecurityAlgorithms.Mldsa44}'.");

            byte[] publicKeyBytes = Base64UrlEncoder.DecodeBytes(publicKey);
            IntPtr mldsaHandle = SymCrypt.SymCryptMlDsakeyAllocate(SYMCRYPT_MLDSA_PARAMS_ENUM.MLDSA44);

            int error = SymCrypt.SymCryptMlDsakeySetValue(
                publicKeyBytes,
                publicKeyBytes.LongLength,
                SYMCRYPT_MLDSAKEY_FORMAT.PUBLIC_KEY,
                0,
                mldsaHandle);

            PublicKey = publicKey;
            Handle = mldsaHandle;
            Algorithm = algorithm;
        }

        /// <summary>
        /// Signs a byte array using ML-DSA
        /// </summary>
        /// <param name="data">The data to sign.</param>
        /// <param name="signature">The Signature.</param>
        /// <remarks>This is an inefficient model, as we should not be allocating here.
        /// Eventually we will follow the model of using the ArrayPool for allocations.</remarks>
        public override void SignData(byte[] data, out byte[] signature)
        {
            if (data == null)
                throw new ArgumentNullException(nameof(data));

            byte[] nullBytes = Array.Empty<byte>();
            long signatureLength = SignatureSize;
            signature = new byte[SignatureSize];
            int error = SymCrypt.SymCryptMlDsaSign(
                Handle,
                data,
                data.Length,
                nullBytes,
                0,
                0,
                signature,
                signatureLength);
        }

        private IntPtr Handle { get; set; }

        /// <summary>
        /// Verifies a signature using ML-DSA
        /// </summary>
        /// <param name="data">The data that was signed.</param>
        /// <param name="signature">The signature that should match.</param>
        /// <returns></returns>
        public override bool VerifyData(byte[] data, byte[] signature)
        {
            if (data == null)
                throw new ArgumentNullException(nameof(data));

            if (signature == null)
                throw new ArgumentNullException(nameof(signature));

            byte[] nullBytes = Array.Empty<byte>();
            int error = SymCrypt.SymCryptMlDsaVerify(
                Handle,
                data,
                data.Length,
                nullBytes,
                0,
                signature,
                signature.Length,
                0);

            return error == 0;
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

                if (Handle != IntPtr.Zero)
                {
                    SymCrypt.SymCryptMlDsakeyFree(Handle);
                    Handle = IntPtr.Zero;
                }
            }
        }
    }
#pragma warning restore RS0016 // Add public types and members to the declared API

}

