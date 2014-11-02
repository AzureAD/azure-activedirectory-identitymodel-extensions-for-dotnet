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

namespace System.IdentityModel.Tokens
{
    using System.Security.Cryptography;
    using System.Security.Cryptography.X509Certificates;

    public class X509AsymmetricSecurityKey : AsymmetricSecurityKey
    {
        X509Certificate2 certificate;
        AsymmetricAlgorithm privateKey;
        bool privateKeyAvailabilityDetermined;
        PublicKey publicKey;
        RSA rsa;

        object thisLock = new Object();

        public X509AsymmetricSecurityKey(X509Certificate2 certificate)
        {
            if (certificate == null)
                throw new ArgumentNullException("certificate");

            this.certificate = certificate;
            this.rsa = this.certificate.PublicKey.Key as RSA;
            if (this.rsa == null)
            {
                throw new CryptographicException("only RSA is supported");
            }
        }

        public override int KeySize
        {
            get { return this.PublicKey.Key.KeySize; }
        }

        AsymmetricAlgorithm PrivateKey
        {
            get
            {
                if (!this.privateKeyAvailabilityDetermined)
                {
                    lock (ThisLock)
                    {
                        if (!this.privateKeyAvailabilityDetermined)
                        {
                            this.privateKey = this.certificate.PrivateKey;
                            this.privateKeyAvailabilityDetermined = true;
                        }
                    }
                }
                return this.privateKey;
            }
        }

        PublicKey PublicKey
        {
            get
            {
                if (this.publicKey == null)
                {
                    lock (ThisLock)
                    {
                        if (this.publicKey == null)
                        {
                            this.publicKey = this.certificate.PublicKey;
                        }
                    }
                }
                return this.publicKey;
            }
        }

        Object ThisLock
        {
            get
            {
                return thisLock;
            }
        }

        public override AsymmetricAlgorithm GetAsymmetricAlgorithm(string algorithm, bool requiresPrivateKey)
        {
            if (string.IsNullOrWhiteSpace("algorithm"))
                throw new ArgumentNullException("algorithm");

            if (requiresPrivateKey && !HasPrivateKey())
            {
                throw new CryptographicException("NoPrivateKeyAvailable");
            }

            if (IsSupportedAlgorithm(algorithm))
            {
                if (requiresPrivateKey)
                    return this.PrivateKey;

                return this.PublicKey.Key;
            }

            throw new CryptographicException("Algorithm not supported: " + algorithm);
        }

        public override HashAlgorithm GetHashAlgorithmForSignature(string algorithm)
        {
            if (string.IsNullOrEmpty(algorithm))
            {
                throw new ArgumentNullException("algorithm");
            }

            switch (algorithm)
            {
                case SecurityAlgorithms.RsaSha1Signature:
                    return SHA1.Create();
                case SecurityAlgorithms.RsaSha256Signature:
                    return SHA256.Create();
                default:
                    throw new CryptographicException("UnsupportedAlgorithmForCryptoOperation: " + algorithm);
            }
        }


        public override bool HasPrivateKey()
        {
            return (this.PrivateKey != null);
        }

        public override bool IsSupportedAlgorithm(string algorithm)
        {
            switch (algorithm)
            {
                case SecurityAlgorithms.RsaSha256Signature:
                    return (this.PublicKey.Key is RSA);
                default:
                    return false;
            }
        }
    }
}
