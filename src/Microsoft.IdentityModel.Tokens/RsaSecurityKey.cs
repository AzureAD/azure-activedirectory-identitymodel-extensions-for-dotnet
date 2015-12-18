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

namespace Microsoft.IdentityModel.Tokens
{
    public class RsaSecurityKey : AsymmetricSecurityKey
    {
        public RsaSecurityKey(RSAParameters rsaParameters)
        {
            // must have private or public key
            HasPrivateKey = rsaParameters.D != null && rsaParameters.DP != null && rsaParameters.DQ != null && rsaParameters.P != null && rsaParameters.Q != null;
            HasPublicKey = rsaParameters.Exponent != null && rsaParameters.Modulus != null;
            if (!HasPrivateKey && !HasPublicKey)
            {
                throw LogHelper.LogException<ArgumentException>("No public or private key material found");
            }

            Parameters = rsaParameters;
        }

        public RsaSecurityKey(RSA rsa)
        {
            if (rsa == null)
                throw LogHelper.LogArgumentNullException("rsa");

            RSACryptoServiceProvider rsaCsp = rsa as RSACryptoServiceProvider;
            if (rsaCsp != null)
            {
                HasPrivateKey = !rsaCsp.PublicOnly;
            }
            else
            {
                // fake signing to determine if the rsa instance has the private key or not is a costly operation especially in case of HSM. We return true by default in that case, it will fail later at the time of signing or decrypting.
                HasPrivateKey = true;
            }
            HasPublicKey = true;
            Rsa = rsa;
        }

        public override bool HasPrivateKey { get; }

        public override bool HasPublicKey { get; }

        public override int KeySize
        {
            get
            {
                if (Rsa != null)
                    return Rsa.KeySize;
                if (HasPublicKey)
                    return Parameters.Modulus.Length * 8;
                else if (HasPrivateKey)
                    return Parameters.D.Length * 8;
                else
                    return 0;
            }
        }

        /// <summary>
        /// <see cref="RSAParameters"/> used to initialize the key.
        /// </summary>
        public RSAParameters Parameters { get; private set; }

        /// <summary>
        /// <see cref="RSA"/> instance used to initialize the key.
        /// </summary>
        public RSA Rsa { get; private set; }

        public override SignatureProvider GetSignatureProvider(string algorithm, bool verifyOnly)
        {
            if (verifyOnly)
                return SignatureProviderFactory.CreateForVerifying(this, algorithm);
            else
                return SignatureProviderFactory.CreateForSigning(this, algorithm);
        }
    }
}
