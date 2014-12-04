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

    sealed public class RsaSecurityKey : AsymmetricSecurityKey
    {
        PrivateKeyStatus privateKeyStatus = PrivateKeyStatus.AvailabilityNotDetermined;
        readonly RSA rsa;
        RSAParameters _rsaParamaeters;

        object hashAlg = null;

        public RsaSecurityKey(RSAParameters parameters)
        {
            _rsaParamaeters = parameters;
        }

        public override int KeySize
        {
            // TODO - brentsch, this shouldn't be fixed size
            get { return 2048; }
        }

        public override bool HasPrivateKey()
        {
            if (this.privateKeyStatus == PrivateKeyStatus.AvailabilityNotDetermined)
            {
                RSACryptoServiceProvider rsaCryptoServiceProvider = this.rsa as RSACryptoServiceProvider;
                if (rsaCryptoServiceProvider != null)
                {
                    this.privateKeyStatus = rsaCryptoServiceProvider.PublicOnly ? PrivateKeyStatus.DoesNotHavePrivateKey : PrivateKeyStatus.HasPrivateKey;
                }
                else
                {
                    try
                    {
                        byte[] hash = new byte[20];
                        this.rsa.DecryptValue(hash); // imitate signing
                        this.privateKeyStatus = PrivateKeyStatus.HasPrivateKey;
                    }
                    catch (CryptographicException)
                    {
                        this.privateKeyStatus = PrivateKeyStatus.DoesNotHavePrivateKey;
                    }
                }
            }
            return this.privateKeyStatus == PrivateKeyStatus.HasPrivateKey;
        }

        public override bool IsSupportedAlgorithm(string algorithm)
        {
            if (string.IsNullOrEmpty(algorithm))
                return false;

            switch (algorithm)
            {
                case SecurityAlgorithms.RsaSha1Signature:
                case SecurityAlgorithms.RsaSha256Signature:
                    return true;
                default:
                    return false;
            }
        }
        //public override byte[] GetPublicBytes()
        //{
        //    return null;
        //}

        //public override byte[] GetPublicAndPrivateBytes()
        //{
        //    return null;
        //}

        public override SignatureProvider GetSignatureProvider(string algorithm)
        {
            return new AsymmetricSignatureProvider(this, algorithm, false);
        }

        public RSAParameters Parameters { get { return _rsaParamaeters; } }

        enum PrivateKeyStatus
        {
            AvailabilityNotDetermined,
            HasPrivateKey,
            DoesNotHavePrivateKey
        }
    }
}
