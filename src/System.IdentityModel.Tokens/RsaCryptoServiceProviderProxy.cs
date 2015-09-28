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
