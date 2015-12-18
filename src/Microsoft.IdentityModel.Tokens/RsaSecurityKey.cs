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

namespace Microsoft.IdentityModel.Tokens
{
    public class RsaSecurityKey : AsymmetricSecurityKey
    {
        private RSAParameters _rsaParamaeters;

        public RsaSecurityKey(RSAParameters rsaParameters)
        {
            // must have private or public key
            bool hasPrivateKey = rsaParameters.D != null && rsaParameters.DP != null && rsaParameters.DQ != null && rsaParameters.P != null && rsaParameters.Q != null;
            bool hasPublicKey = rsaParameters.Exponent != null && rsaParameters.Modulus != null;
            if (!hasPrivateKey && !hasPublicKey)
            {
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
