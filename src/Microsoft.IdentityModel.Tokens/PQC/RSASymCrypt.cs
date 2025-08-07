// Copyright (c) Microsoft Corporation. All rights reserved.
// Licensed under the MIT License.

using System;
using System.Security.Cryptography;

namespace Microsoft.IdentityModel.Tokens
{
#pragma warning disable RS0016 // Add public types and members to the declared API

    /// <summary>
    /// Represents a security algorithm is used for MLDSA.
    /// AsymmetricAdapter will need to be expanded so we will have a pool of these types.
    /// </summary>
    public class RsaSymCrypt : AsymmetricAlgorithm
    {
        private bool _disposed;
        private int _keySize;

        /// <summary>
        /// Creates a random <see cref="AsymmetricAlgorithm"/> that supports RSA.
        /// </summary>
        /// <param name="keySize"></param>
        /// <returns>A crypto algorithm that calls directly into SymCrypt for RSA operations.</returns>
        public RsaSymCrypt(int keySize)
        {
            _keySize = keySize;
            SignatureSize = keySize / 8;

            SYMCRYPT_RSA_PARAMS rsaParams = new SYMCRYPT_RSA_PARAMS
            {
                version = 1,
                nBitsOfModulus = (uint)keySize,
                nPrimes = 2,
                nPubExp = 1
            };

#pragma warning disable CA1031 // Do not catch general exception types
            try
            {
                // Initialize the key structure
                Handle = SymCrypt.SymCryptRsakeyAllocate(ref rsaParams, 0);
                if (Handle == IntPtr.Zero)
                    throw new CryptographicException("Failed to allocate RSA key.");

                uint rsaKeySize = SymCrypt.SymCryptSizeofRsakeyFromParams(ref rsaParams);

                byte[] rsaKeyFormat = new byte[rsaKeySize];
                long cb = (long)rsaKeySize;
                IntPtr rsaKey = SymCrypt.SymCryptRsakeyCreate(rsaKeyFormat, cb, ref rsaParams);

                if (rsaKey == IntPtr.Zero)
                    throw new CryptographicException("Failed to create RSA key.");

                // Initialize the key
                int error = SymCrypt.SymCryptRsakeyGenerate(rsaKey, null, 0, 1);

                bool hasPrivateKey = SymCrypt.SymCryptRsakeyHasPrivateKey(rsaKey);
                if (!hasPrivateKey)
                    throw new CryptographicException("Failed to create RSA key with private key.");

                byte[] bytesToHash = Guid.NewGuid().ToByteArray();
                long cbHash = bytesToHash.Length;
                byte[] hash = new byte[32];
                SymCrypt.SymCryptSha256(bytesToHash, cbHash, hash);

                // Initialize the key
                //int error = SymCrypt.SymCryptRsakeyGenerate(Handle, 0);
                //if (error != 0)
                //    throw new CryptographicException($"Failed to generate RSA key. Error code: {error}");
            }
            catch (Exception ex)
            {
                Console.WriteLine($"Error allocating RSA key: {ex.Message}");
            }
#pragma warning restore CA1031 // Do not catch general exception types
        }

        /// <summary>
        /// The handle to the key returned from SymCrypt.
        /// </summary>
        private IntPtr Handle { get; set; }

        internal long SignatureSize { get; set; }

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

            long cbHash = data.LongLength;
            // adjust for different hash sizes, assuming SHA256
            byte[] hashSymCrypt = new byte[32];

            SymCrypt.SymCryptSha256(data, cbHash, hashSymCrypt);
            IntPtr hashSymCryptPtr = SymCrypt.SymCryptSha256Algorithm();

            signature = new byte[SignatureSize];
            int retVal = SymCrypt.SymCryptRsaPssSign(
                Handle,
                hashSymCrypt,
                hashSymCrypt.Length,
                SymCrypt.SymCryptSha256Algorithm(),
                32,
                0,
                SYMCRYPT_NUMBER_FORMAT.MSB_FIRST,
                signature,
                signature.Length,
                ref cbHash);
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

