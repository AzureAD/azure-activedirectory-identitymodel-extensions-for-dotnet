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

    public class RsaSecurityKey : AsymmetricSecurityKey
    {
        private RSAParameters _rsaParamaeters;

        public RsaSecurityKey(RSAParameters rsaParameters)
        {
            // must have private or public key
            // TODO - brentsch, D.Length must == Modulus.Length

            if (   !(rsaParameters.D == null || rsaParameters.DP == null || rsaParameters.DQ == null || rsaParameters.P == null || rsaParameters.Q == null)
                && !(rsaParameters.Exponent == null || rsaParameters.Modulus == null))
            {
                // TODO - brentsch - error message
                throw new ArgumentException("no public or private key material found");
            }

            _rsaParamaeters = rsaParameters;
        }

        public override int KeySize
        {
            get
            {
                if (HasPublicKey)
                    return _rsaParamaeters.Modulus.Length * 8;
                else if (HasPrivateKey)
                    return _rsaParamaeters.D.Length * 8;
                else
                    return 0;
            }
        }

        public override bool HasPrivateKey
        {
            get
            {
                return !(_rsaParamaeters.D == null || _rsaParamaeters.DP == null || _rsaParamaeters.DQ == null || _rsaParamaeters.P == null || _rsaParamaeters.Q == null);
            }
        }

        public override bool HasPublicKey
        {
            get
            {
                return !(_rsaParamaeters.Exponent == null || _rsaParamaeters.Modulus == null);
            }
        }

        public override bool IsSupportedAlgorithm(string algorithm)
        {
            return SignatureProviderFactory.IsSupportedAlgorithm(this, algorithm);
        }

        public override SignatureProvider GetSignatureProvider(string algorithm, bool verifyOnly)
        {
            if (verifyOnly)
                return SignatureProviderFactory.CreateForVerifying(this, algorithm);
            else
                return SignatureProviderFactory.CreateForSigning(this, algorithm);
        }

        public RSAParameters Parameters
        {
            get
            {
                return _rsaParamaeters;
            }
        }
    }
}
