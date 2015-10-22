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
using Microsoft.IdentityModel.Logging;

namespace System.IdentityModel.Tokens
{
    /// <summary>
    /// The purpose of this class is to ensure that we obtain an RsaCryptoServiceProvider that supports SHA-256 signatures.
    /// If the original RsaCryptoServiceProvider doesn't support SHA-256, we create a new one using the same KeyContainer.
    /// </summary>
    public class RSACryptoServiceProviderProxy : IDisposable
    {
        private const int PROV_RSA_AES = 24;    // CryptoApi provider type for an RSA provider supporting sha-256 digital signatures

        private bool disposed;
        
        // Only dispose of the RsaCryptoServiceProvider object if we created a new instance that supports SHA-256,
        // otherwise do not disposed of the referenced RsaCryptoServiceProvider
        private bool disposeRsa;

        private RSACryptoServiceProvider rsa;

        public RSACryptoServiceProviderProxy(RSACryptoServiceProvider rsa)
        {
            if (rsa == null)
            {
                LogHelper.Throw(LogMessages.IDX10507, typeof(ArgumentException));
                return;
            }

            //
            // If the provider does not understand SHA256, 
            // replace it with one that does.
            //
            if (rsa.CspKeyContainerInfo.ProviderType != PROV_RSA_AES)
            {
                CspParameters csp = new CspParameters();
                csp.ProviderType = PROV_RSA_AES;
                csp.KeyContainerName = rsa.CspKeyContainerInfo.KeyContainerName;
                csp.KeyNumber = (int)rsa.CspKeyContainerInfo.KeyNumber;
                if (rsa.CspKeyContainerInfo.MachineKeyStore)
                {
                    csp.Flags = CspProviderFlags.UseMachineKeyStore;
                }

                //
                // If UseExistingKey is not specified, the CLR will generate a key for a non-existent group.
                // With this flag, a CryptographicException is thrown instead.
                //
                csp.Flags |= CspProviderFlags.UseExistingKey;

                this.rsa = new RSACryptoServiceProvider(csp);

                // since we created a new RsaCryptoServiceProvider we need to dispose it
                this.disposeRsa = true;
            }
            else
            {
                // no work-around necessary
                this.rsa = rsa;
            }
        }

        ~RSACryptoServiceProviderProxy()
        {
            this.Dispose(false);
        }

        public void Dispose()
        {
            this.Dispose(true);
            GC.SuppressFinalize(this);
        }

        public byte[] SignData(byte[] signingInput, object hash)
        {
            return this.rsa.SignData(signingInput, hash);
        }

        public bool VerifyData(byte[] signingInput, object hash, byte[] signature)
        {
            return this.rsa.VerifyData(signingInput, hash, signature);
        }

        private void Dispose(bool disposing)
        {
            if (!this.disposed)
            {
                if (disposing)
                {
                    if (this.disposeRsa && this.rsa != null)
                    {
                        this.rsa.Dispose();
                        this.rsa = null;
                    }
                }

                this.disposed = true;
            }
        }
    }
}
