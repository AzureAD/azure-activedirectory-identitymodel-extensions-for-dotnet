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
using System.IdentityModel.Tokens.Jwt;
using System.Text;
using System.Threading.Tasks;
using Microsoft.IdentityModel.JsonWebTokens;
using Microsoft.IdentityModel.TestUtils;
using Xunit;

#pragma warning disable CS3016 // Arrays as attribute arguments is not CLS-compliant

namespace Microsoft.IdentityModel.Tokens.Tests
{
    public class MultiThreadingTokenTests
    {
        [Theory, MemberData(nameof(RoundTripSecurityTokensTheoryData))]
        public void RoundTripSecurityTokens(RoundTripTokenTheoryData theoryData)
        {
            TestUtilities.WriteHeader($"{this}.ValidateJwtSecurityTokens", theoryData);
            var context = new CompareContext($"{this}.ValidateJwtSecurityTokens, {theoryData.TestId}");
            var numberOfErrors = 0;
            void action()
            {
                var jwt = theoryData.JwtSecurityTokenHandler.CreateEncodedJwt(theoryData.TokenDescriptor);
                var claimsPrincipal = theoryData.JwtSecurityTokenHandler.ValidateToken(theoryData.Jwt, theoryData.ValidationParameters, out SecurityToken _);
                var tokenValidationResult = theoryData.JsonWebTokenHandler.ValidateToken(theoryData.Jwt, theoryData.ValidationParameters);

                if (tokenValidationResult.Exception != null && tokenValidationResult.IsValid)
                        context.Diffs.Add("tokenValidationResult.IsValid, tokenValidationResult.Exception != null");

                if (!tokenValidationResult.IsValid)
                {
                    numberOfErrors++;
                    if (tokenValidationResult.Exception != null)
                        throw tokenValidationResult.Exception;
                    else
                        throw new SecurityTokenException("something failed");
                }
            }

            var actions = new Action[1000];
            for (int i = 0; i < actions.Length; i++)
                actions[i] = action;

            try
            {
                Parallel.Invoke(actions);
                theoryData.ExpectedException.ProcessNoException();
            }
            catch (Exception ex)
            {
                theoryData.ExpectedException.ProcessException(ex, context);
            }

            if (numberOfErrors > 0)
                context.AddDiff($"Number of errors: '{numberOfErrors}'.");

            TestUtilities.AssertFailIfErrors(context);
        }

        public static TheoryData<RoundTripTokenTheoryData> RoundTripSecurityTokensTheoryData
        {
            get
            {
                var jwtSymmetric = (new JwtSecurityTokenHandler()).CreateEncodedJwt(Default.SymmetricSignSecurityTokenDescriptor(Default.Claims));
                var validationParametersSymmetric = Default.SymmetricSignTokenValidationParameters;
                var jwtAsymmetric = (new JwtSecurityTokenHandler()).CreateEncodedJwt(Default.AsymmetricSignSecurityTokenDescriptor(Default.Claims));
                var validationParametersAsymmetric = Default.AsymmetricSignTokenValidationParameters;
                var validationParametersAsymmetricEncryptSignToken = Default.AsymmetricEncryptSignTokenValidationParameters;
                var securityTokenDescriptor = Default.AsymmetricSignSecurityTokenDescriptor(Default.SamlClaims);
                securityTokenDescriptor.Claims = Default.PayloadDictionary;


                SignatureProvider = CryptoProviderFactory.Default.CreateForVerifying(Default.AsymmetricSignTokenValidationParameters.IssuerSigningKey, KeyingMaterial.DefaultX509SigningCreds_2048_RsaSha2_Sha2.Algorithm);
                return new TheoryData<RoundTripTokenTheoryData>()
                {
                    new RoundTripTokenTheoryData
                    {
                        JwtSecurityTokenHandler = new JwtSecurityTokenHandler(),
                        JsonWebTokenHandler = new JsonWebTokenHandler(),
                        Jwt = jwtSymmetric,
                        TestId = "SymmetricJwt",
                        TokenDescriptor = securityTokenDescriptor,
                        ValidationParameters = validationParametersSymmetric
                    },
                    new RoundTripTokenTheoryData
                    {
                        JwtSecurityTokenHandler = new JwtSecurityTokenHandler(),
                        JsonWebTokenHandler = new JsonWebTokenHandler(),
                        Jwt = jwtAsymmetric,
                        TestId = "AsymmetricJwt",
                        TokenDescriptor = securityTokenDescriptor,
                        ValidationParameters = validationParametersAsymmetric
                    },
                    new RoundTripTokenTheoryData
                    {
                        JwtSecurityTokenHandler = new JwtSecurityTokenHandler(),
                        JsonWebTokenHandler = new JsonWebTokenHandler(),
                        Jwt = jwtAsymmetric,
                        TestId = "EncryptedJwt",
                        TokenDescriptor = securityTokenDescriptor,
                        ValidationParameters = validationParametersAsymmetricEncryptSignToken
                    },
                };
            }
        }

        public static SignatureProvider SignatureProvider { get; set; }

        public static SecurityToken SignatureValidator(string token, TokenValidationParameters validationParameters)
        {
            var jwtToken = new JsonWebToken(token);
            var encodedBytes = Encoding.UTF8.GetBytes(jwtToken.EncodedHeader + "." + jwtToken.EncodedPayload);
            var signatureBytes = Base64UrlEncoder.DecodeBytes(jwtToken.EncodedSignature);

            if (!SignatureProvider.Verify(encodedBytes, signatureBytes))
                throw new SecurityTokenValidationException("sig failed");

            return jwtToken;
        }
    }

    public class RoundTripTokenTheoryData : TheoryDataBase
    {
        public string Payload { get; set; }

        public string CompressionAlgorithm { get; set; }

        public CompressionProviderFactory CompressionProviderFactory { get; set; }

        public EncryptingCredentials EncryptingCredentials { get; set; }

        public bool IsValid { get; set; } = true;

        public string Jwt { get; set; }

        public SigningCredentials SigningCredentials { get; set; }

        public SecurityTokenDescriptor TokenDescriptor { get; set; }

        public JsonWebTokenHandler JsonWebTokenHandler { get; set; }

        public JwtSecurityTokenHandler JwtSecurityTokenHandler { get; set; }

        public TokenValidationParameters ValidationParameters { get; set; }
    }
}

#pragma warning restore CS3016 // Arrays as attribute arguments is not CLS-compliant
