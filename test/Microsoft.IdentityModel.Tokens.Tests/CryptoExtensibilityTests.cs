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

using System.IdentityModel.Tokens.Jwt;
using Xunit;

namespace Microsoft.IdentityModel.Tokens.Tests
{
    /// <summary>
    /// Crypto extensibility scenarios
    /// </summary>
    public class CryptoExtensibilityTests
    {
        /// <summary>
        /// SecurityTokenDescriptor.CryptoProviderFactory has priority over SecurityKey.CryptoProviderFactory
        /// </summary>
#pragma warning disable CS3016 // Arrays as attribute arguments is not CLS-compliant
        [Theory, MemberData("SecurityTokenDescriptorDataSet")]
#pragma warning restore CS3016 // Arrays as attribute arguments is not CLS-compliant
        public void CryptoProviderOrderingWhenSigning(SecurityTokenDescriptor tokenDescriptor)
        {
            var tokenHandler = new JwtSecurityTokenHandler();
            var jwt = tokenHandler.CreateEncodedJwt(tokenDescriptor);

            if (tokenDescriptor.SigningCredentials.CryptoProviderFactory == null)
            {
                Assert.True((tokenDescriptor.SigningCredentials.Key.CryptoProviderFactory as CustomCryptoProviderFactory).CreateForSigningCalled);
                Assert.True((tokenDescriptor.SigningCredentials.Key.CryptoProviderFactory as CustomCryptoProviderFactory).ReleaseSignatureProviderCalled);
                Assert.True(((tokenDescriptor.SigningCredentials.Key.CryptoProviderFactory as CustomCryptoProviderFactory).SignatureProvider as CustomSignatureProvider).SignCalled);
                Assert.True(((tokenDescriptor.SigningCredentials.Key.CryptoProviderFactory as CustomCryptoProviderFactory).SignatureProvider as CustomSignatureProvider).DisposeCalled);
            }
            else
            {
                Assert.True((tokenDescriptor.SigningCredentials.CryptoProviderFactory as CustomCryptoProviderFactory).CreateForSigningCalled);
                Assert.True((tokenDescriptor.SigningCredentials.CryptoProviderFactory as CustomCryptoProviderFactory).ReleaseSignatureProviderCalled);
                Assert.True(((tokenDescriptor.SigningCredentials.CryptoProviderFactory as CustomCryptoProviderFactory).SignatureProvider as CustomSignatureProvider).SignCalled);
                Assert.True(((tokenDescriptor.SigningCredentials.CryptoProviderFactory as CustomCryptoProviderFactory).SignatureProvider as CustomSignatureProvider).DisposeCalled);
                Assert.False((tokenDescriptor.SigningCredentials.Key.CryptoProviderFactory as CustomCryptoProviderFactory).CreateForSigningCalled);
                Assert.False((tokenDescriptor.SigningCredentials.Key.CryptoProviderFactory as CustomCryptoProviderFactory).ReleaseSignatureProviderCalled);
                Assert.False(((tokenDescriptor.SigningCredentials.Key.CryptoProviderFactory as CustomCryptoProviderFactory).SignatureProvider as CustomSignatureProvider).SignCalled);
                Assert.False(((tokenDescriptor.SigningCredentials.Key.CryptoProviderFactory as CustomCryptoProviderFactory).SignatureProvider as CustomSignatureProvider).DisposeCalled);
            }
        }

        public static TheoryData<SecurityTokenDescriptor> SecurityTokenDescriptorDataSet
        {
            get
            {
                var dataset = new TheoryData<SecurityTokenDescriptor>();

                var key = new SymmetricSecurityKey(new byte[256]);
                key.CryptoProviderFactory = new CustomCryptoProviderFactory()
                {
                    SignatureProvider = new CustomSignatureProvider(key, "alg")
                };

                var tokenDescriptor = IdentityUtilities.DefaultSecurityTokenDescriptor(new SigningCredentials(key, "alg"));

                dataset.Add(tokenDescriptor);

                key = new SymmetricSecurityKey(new byte[256]);
                key.CryptoProviderFactory = new CustomCryptoProviderFactory()
                {
                    SignatureProvider = new CustomSignatureProvider(key, "alg")
                };

                tokenDescriptor = IdentityUtilities.DefaultSecurityTokenDescriptor(new SigningCredentials(key, "alg"));
                tokenDescriptor.SigningCredentials.CryptoProviderFactory = new CustomCryptoProviderFactory()
                {
                    SignatureProvider = new CustomSignatureProvider(key, "alg")
                };

                dataset.Add(tokenDescriptor);
                return dataset;
            }
        }

        /// <summary>
        /// TokenValidationParameters.CryptoProviderFactory has priority over SecurityKey.CryptoProviderFactory
        /// </summary>
#pragma warning disable CS3016 // Arrays as attribute arguments is not CLS-compliant
        [Theory, MemberData("SigningCredentialsDataSet")]
#pragma warning restore CS3016 // Arrays as attribute arguments is not CLS-compliant
        public void CryptoProviderOrderingWhenVerifying(TokenValidationParameters validationParameters, string jwt)
        {
            var tokenHandler = new JwtSecurityTokenHandler();
            SecurityToken token = null;
            tokenHandler.ValidateToken(jwt, validationParameters, out token);

            if (validationParameters.CryptoProviderFactory == null)
            {
                Assert.True((validationParameters.IssuerSigningKey.CryptoProviderFactory as CustomCryptoProviderFactory).CreateForVerifyingCalled);
                Assert.True((validationParameters.IssuerSigningKey.CryptoProviderFactory as CustomCryptoProviderFactory).ReleaseSignatureProviderCalled);
                Assert.True(((validationParameters.IssuerSigningKey.CryptoProviderFactory as CustomCryptoProviderFactory).SignatureProvider as CustomSignatureProvider).VerifyCalled);
                Assert.True(((validationParameters.IssuerSigningKey.CryptoProviderFactory as CustomCryptoProviderFactory).SignatureProvider as CustomSignatureProvider).DisposeCalled);
            }
            else
            {
                Assert.True((validationParameters.CryptoProviderFactory as CustomCryptoProviderFactory).CreateForVerifyingCalled);
                Assert.True((validationParameters.CryptoProviderFactory as CustomCryptoProviderFactory).ReleaseSignatureProviderCalled);
                Assert.True(((validationParameters.CryptoProviderFactory as CustomCryptoProviderFactory).SignatureProvider as CustomSignatureProvider).VerifyCalled);
                Assert.True(((validationParameters.CryptoProviderFactory as CustomCryptoProviderFactory).SignatureProvider as CustomSignatureProvider).DisposeCalled);
                Assert.False((validationParameters.IssuerSigningKey.CryptoProviderFactory as CustomCryptoProviderFactory).CreateForVerifyingCalled);
                Assert.False((validationParameters.IssuerSigningKey.CryptoProviderFactory as CustomCryptoProviderFactory).ReleaseSignatureProviderCalled);
                Assert.False(((validationParameters.IssuerSigningKey.CryptoProviderFactory as CustomCryptoProviderFactory).SignatureProvider as CustomSignatureProvider).VerifyCalled);
                Assert.False(((validationParameters.IssuerSigningKey.CryptoProviderFactory as CustomCryptoProviderFactory).SignatureProvider as CustomSignatureProvider).DisposeCalled);
            }
        }

        public static TheoryData<TokenValidationParameters, string> SigningCredentialsDataSet
        {
            get
            {
                var dataset = new TheoryData<TokenValidationParameters, string>();
                var jwt = IdentityUtilities.DefaultAsymmetricJwt;

                var validationParameters = IdentityUtilities.DefaultAsymmetricTokenValidationParameters;
                validationParameters.IssuerSigningKey.CryptoProviderFactory = new CustomCryptoProviderFactory()
                {
                    SignatureProvider = new CustomSignatureProvider(validationParameters.IssuerSigningKey, "alg")
                };

                dataset.Add(validationParameters, jwt);

                validationParameters = IdentityUtilities.DefaultAsymmetricTokenValidationParameters;
                validationParameters.IssuerSigningKey.CryptoProviderFactory = new CustomCryptoProviderFactory()
                {
                    SignatureProvider = new CustomSignatureProvider(validationParameters.IssuerSigningKey, "alg")
                };

                validationParameters.CryptoProviderFactory = new CustomCryptoProviderFactory()
                {
                    SignatureProvider = new CustomSignatureProvider(validationParameters.IssuerSigningKey, "alg")
                };

                dataset.Add(validationParameters, jwt);

                return dataset;
            }
        }

    }
}
