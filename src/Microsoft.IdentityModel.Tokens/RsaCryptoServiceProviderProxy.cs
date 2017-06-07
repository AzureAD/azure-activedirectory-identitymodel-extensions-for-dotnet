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

#if NET451 || NET45

using System;
using System.Security.Cryptography;
using Microsoft.IdentityModel.Logging;

namespace Microsoft.IdentityModel.Tokens
{
    /// <summary>
    /// The purpose of this class is to ensure that we obtain an RsaCryptoServiceProvider that supports SHA-256 signatures.
    /// If the original RsaCryptoServiceProvider doesn't support SHA-256, we create a new one using the same KeyContainer.
    /// </summary>
    public class RSACryptoServiceProviderProxy : IDisposable
    {
        private const int PROV_RSA_AES = 24;    // CryptoApi provider type for an RSA provider supporting sha-256 digital signatures

        // CryptoApi provider type for an RSA provider only supporting sha1 digital signatures
        private const int PROV_RSA_FULL = 1;
        private const int PROV_RSA_SCHANNEL = 12;

        private bool _disposed;

        // Only dispose of the RsaCryptoServiceProvider object if we created a new instance that supports SHA-256,
        // otherwise do not disposed of the referenced RsaCryptoServiceProvider
        private bool _disposeRsa;
        private RSACryptoServiceProvider _rsa;

        /// <summary>
        /// Initializes an new instance of <see cref="RSACryptoServiceProviderProxy"/>.
        /// </summary>
        /// <param name="rsa"><see cref="RSACryptoServiceProvider"/></param>
        public RSACryptoServiceProviderProxy(RSACryptoServiceProvider rsa)
        {
            if (rsa == null)
                throw LogHelper.LogArgumentNullException("rsa");

            //
            // Level up the provider type only if:
            // 1. it is PROV_RSA_FULL or PROV_RSA_SCHANNEL which denote CSPs that only understand Sha1 algorithms
            // 2. it is not associated with a hardware key
            if ((rsa.CspKeyContainerInfo.ProviderType == PROV_RSA_FULL || rsa.CspKeyContainerInfo.ProviderType == PROV_RSA_SCHANNEL) && !rsa.CspKeyContainerInfo.HardwareDevice)
            {
                CspParameters csp = new CspParameters();
                csp.ProviderType = PROV_RSA_AES;
                csp.KeyContainerName = rsa.CspKeyContainerInfo.KeyContainerName;
                csp.KeyNumber = (int)rsa.CspKeyContainerInfo.KeyNumber;
                if (rsa.CspKeyContainerInfo.MachineKeyStore)
                    csp.Flags = CspProviderFlags.UseMachineKeyStore;

                // If UseExistingKey is not specified, the CLR will generate a key for a non-existent group.
                // With this flag, a CryptographicException is thrown instead.
                csp.Flags |= CspProviderFlags.UseExistingKey;

                _rsa = new RSACryptoServiceProvider(csp);

                // since we created a new RsaCryptoServiceProvider we need to dispose it
                _disposeRsa = true;
            }
            else
            {
                // no work-around necessary
                _rsa = rsa;
            }
        }

        /// <summary>
        /// Destructs the <see cref="RSACryptoServiceProviderProxy"/> instance.
        /// </summary>
        ~RSACryptoServiceProviderProxy()
        {
            this.Dispose(false);
        }

        /// <summary>
        /// Releases all resources used by the current instance of the <see cref="RSACryptoServiceProviderProxy"/> class.
        /// </summary>
        public void Dispose()
        {
            this.Dispose(true);
            GC.SuppressFinalize(this);
        }

        /// <summary>
        /// Decrypts data with the System.Security.Cryptography.RSA algorithm.
        /// </summary>
        /// <param name="input">The data to be decrypted.</param>
        /// <param name="fOAEP">true to perform direct System.Security.Cryptography.RSA decryption using OAEP padding (only available on a computer running Microsoft Windows XP or later);o
        /// therwise, false to use PKCS#1 v1.5 padding.</param>
        /// <returns></returns>
        public byte[] Decrypt(byte[] input, bool fOAEP)
        {
            return _rsa.Decrypt(input, fOAEP);
        }

        /// <summary>
        ///  Encrypts data with the System.Security.Cryptography.RSA algorithm.
        /// </summary>
        /// <param name="input">The data to be encrypted.</param>
        /// <param name="fOAEP">true to perform direct System.Security.Cryptography.RSA encryption using OAEP padding (only available on a computer running Microsoft Windows XP or later); 
        /// otherwise, false to use PKCS#1 v1.5 padding.</param>
        /// <returns></returns>
        public byte[] Encrypt(byte[] input, bool fOAEP)
        {
            return _rsa.Encrypt(input, fOAEP);
        }

        /// <summary>
        /// Computes the hash value of the specified byte array using the specified hash algorithm, and signs the resulting hash value.
        /// </summary>
        /// <param name="signingInput">The input byte array for which to compute the hash.</param>
        /// <param name="hash">The hash algorithm to use to create the hash value. </param>
        /// <returns>The <see cref="RSA"/> Signature for the specified data.</returns>
        public byte[] SignData(byte[] signingInput, object hash)
        {
            return _rsa.SignData(signingInput, hash);
        }

        /// <summary>
        /// Verifies that a digital signature is valid by determining the hash value in the signature using the provided public key and comparing it to the hash value of the provided data.
        /// </summary>
        /// <param name="signingInput">The input byte array.</param>
        /// <param name="hash">The hash algorithm to use to create the hash value.</param>
        /// <param name="signature">The signature byte array to be verified.</param>
        /// <returns>true if the signature is valid; otherwise, false.</returns>
        public bool VerifyData(byte[] signingInput, object hash, byte[] signature)
        {
            return _rsa.VerifyData(signingInput, hash, signature);
        }

        private void Dispose(bool disposing)
        {
            if (!_disposed)
            {
                if (disposing)
                {
                    if (_disposeRsa && _rsa != null)
                    {
                        _rsa.Dispose();
                        _rsa = null;
                    }
                }

                _disposed = true;
            }
        }
    }
}
#endif
