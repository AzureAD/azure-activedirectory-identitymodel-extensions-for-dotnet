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

#if NET472 || NETCOREAPP3_1

using System;
using System.Collections;
using System.Collections.Generic;
using Microsoft.IdentityModel.Json.Linq;
using Microsoft.IdentityModel.JsonWebTokens;
using Microsoft.IdentityModel.TestUtils;
using Microsoft.IdentityModel.Tokens;
using Xunit;


using KEY = Microsoft.IdentityModel.TestUtils.KeyingMaterial;

#pragma warning disable CS3016 // Arrays as attribute arguments is not CLS-compliant

namespace Microsoft.IdentityModel.Tokens.Tests
{
    public class JweUsingEcdhEsTests
    {
        [Theory, MemberData(nameof(CreateEcdhEsTestcases))]
        public void CreateJweEcdhEsTests(CreateEcdhEsTheoryData theoryData)
        {
            var context = TestUtilities.WriteHeader($"{this}.CreateJweEcdhEsTests", theoryData);
            try
            {
                JsonWebTokenHandler jsonWebTokenHandler = new JsonWebTokenHandler();

                // Do we need an extension to EncryptingCredentials for: ApuSender, ApvSender
                string jwe = jsonWebTokenHandler.CreateToken(
                    Default.PayloadString,
                    Default.AsymmetricSigningCredentials,
                    theoryData.EncryptingCredentials,
                    theoryData.AdditionalHeaderParams);

                JsonWebToken jsonWebToken = new JsonWebToken(jwe);
                // we need the ECDSASecurityKey for the receiver to validate, use TokenValidationParameters.TokenDecryptionKey
                TokenValidationResult tokenValidationResult = jsonWebTokenHandler.ValidateToken(jwe, theoryData.TokenValidationParameters);

                // adjusted for theoryData.ExpectedException == tokenValidationResult.Exception
                if (tokenValidationResult.IsValid != theoryData.ExpectedIsValid)
                    context.AddDiff($"tokenValidationResult.IsValid != theoryData.ExpectedIsValid");

                theoryData.ExpectedException.ProcessNoException(context);
            }
            catch (Exception ex)
            {
                theoryData.ExpectedException.ProcessException(ex, context);
            }

            TestUtilities.AssertFailIfErrors(context);
        }

        public static TheoryData<CreateEcdhEsTheoryData> CreateEcdhEsTestcases
        {
            get
            {
                TheoryData<CreateEcdhEsTheoryData> theoryData = new TheoryData<CreateEcdhEsTheoryData>();

                theoryData.Add(EcdhEsCurveP256AEnc256KW());
                theoryData.Add(EcdhEsCurveP256AEnc256KWNullApuApv());
                theoryData.Add(EcdhEsCurveP384EncA256KW());
                theoryData.Add(EcdhEsCurveP512EncA256KW());
                theoryData.Add(EcdhEsCurveP256EncA192KW()); 
                theoryData.Add(EcdhEsCurveP256EncA128KW());

                return theoryData;
            }
        }

        private static CreateEcdhEsTheoryData EcdhEsCurveP256AEnc256KW()
        {
            CreateEcdhEsTheoryData testData = new CreateEcdhEsTheoryData("EcdhEsCurveP256AEnc256KW")
            {
                EncryptingCredentials = new EncryptingCredentials(
                                    new ECDsaSecurityKey(KeyingMaterial.JsonWebKeyP256, true),
                                    SecurityAlgorithms.EcdhEsA256kw,
                                    SecurityAlgorithms.Aes128CbcHmacSha256)
                {
                    KeyExchangePublicKey = KeyingMaterial.JsonWebKeyP256_Public
                },
                PublicKeyReceiver = KeyingMaterial.JsonWebKeyP256_Public,
                PublicKeySender = KeyingMaterial.JsonWebKeyP256_Public,
                PrivateKeyReceiver = KeyingMaterial.JsonWebKeyP256,
                TokenValidationParameters = new TokenValidationParameters()
                {
                    TokenDecryptionKey = new ECDsaSecurityKey(KeyingMaterial.JsonWebKeyP256, true),
                    ValidAudience = Default.Audience,
                    ValidIssuer = Default.Issuer,
                    IssuerSigningKey = Default.AsymmetricSigningKey
                },
                ApuSender = "SenderInfo",
                ApvSender = "ReceivererInfo"
            };

            var epkJObject = new JObject();
            epkJObject.Add(JsonWebKeyParameterNames.Kty, testData.PublicKeySender.Kty);
            epkJObject.Add(JsonWebKeyParameterNames.Crv, testData.PublicKeySender.Crv);
            epkJObject.Add(JsonWebKeyParameterNames.X, testData.PublicKeySender.X);
            epkJObject.Add(JsonWebKeyParameterNames.Y, testData.PublicKeySender.Y);
            testData.AdditionalHeaderParams = new Dictionary<string, object>();
            testData.AdditionalHeaderParams.Add(JwtHeaderParameterNames.Apu, testData.ApuSender);
            testData.AdditionalHeaderParams.Add(JwtHeaderParameterNames.Apv, testData.ApvSender);
            testData.AdditionalHeaderParams.Add(JwtHeaderParameterNames.Epk, epkJObject);

            return testData;
        }

        private static CreateEcdhEsTheoryData EcdhEsCurveP256AEnc256KWNullApuApv()
        {
            CreateEcdhEsTheoryData testData = new CreateEcdhEsTheoryData("EcdhEsCurveP256AEnc256KW")
            {
                EncryptingCredentials = new EncryptingCredentials(
                                    new ECDsaSecurityKey(KeyingMaterial.JsonWebKeyP256, true),
                                    SecurityAlgorithms.EcdhEsA256kw,
                                    SecurityAlgorithms.Aes128CbcHmacSha256)
                {
                    KeyExchangePublicKey = KeyingMaterial.JsonWebKeyP256_Public
                },
                PublicKeyReceiver = KeyingMaterial.JsonWebKeyP256_Public,
                PublicKeySender = KeyingMaterial.JsonWebKeyP256_Public,
                PrivateKeyReceiver = KeyingMaterial.JsonWebKeyP256,
                TokenValidationParameters = new TokenValidationParameters()
                {
                    TokenDecryptionKey = new ECDsaSecurityKey(KeyingMaterial.JsonWebKeyP256, true),
                    ValidAudience = Default.Audience,
                    ValidIssuer = Default.Issuer,
                    IssuerSigningKey = Default.AsymmetricSigningKey
                },
                ApuSender = null,
                ApvSender = null
            };

            var epkJObject = new JObject();
            epkJObject.Add(JsonWebKeyParameterNames.Kty, testData.PublicKeySender.Kty);
            epkJObject.Add(JsonWebKeyParameterNames.Crv, testData.PublicKeySender.Crv);
            epkJObject.Add(JsonWebKeyParameterNames.X, testData.PublicKeySender.X);
            epkJObject.Add(JsonWebKeyParameterNames.Y, testData.PublicKeySender.Y);
            testData.AdditionalHeaderParams = new Dictionary<string, object>();
            testData.AdditionalHeaderParams.Add(JwtHeaderParameterNames.Apu, testData.ApuSender);
            testData.AdditionalHeaderParams.Add(JwtHeaderParameterNames.Apv, testData.ApvSender);
            testData.AdditionalHeaderParams.Add(JwtHeaderParameterNames.Epk, epkJObject);

            return testData;
        }

        private static CreateEcdhEsTheoryData EcdhEsCurveP384EncA256KW()
        {
            CreateEcdhEsTheoryData testData = new CreateEcdhEsTheoryData("EcdhEsCurveP384EncA256KW")
            {
                EncryptingCredentials = new EncryptingCredentials(
                                    new ECDsaSecurityKey(KeyingMaterial.JsonWebKeyP384, true),
                                    SecurityAlgorithms.EcdhEsA256kw,
                                    SecurityAlgorithms.Aes128CbcHmacSha256)
                {
                    KeyExchangePublicKey = KeyingMaterial.JsonWebKeyP384_Public
                },
                PublicKeyReceiver = KeyingMaterial.JsonWebKeyP384_Public,
                PublicKeySender = KeyingMaterial.JsonWebKeyP384_Public,
                PrivateKeyReceiver = KeyingMaterial.JsonWebKeyP384,
                TokenValidationParameters = new TokenValidationParameters()
                {
                    TokenDecryptionKey = new ECDsaSecurityKey(KeyingMaterial.JsonWebKeyP384, true),
                    ValidAudience = Default.Audience,
                    ValidIssuer = Default.Issuer,
                    IssuerSigningKey = Default.AsymmetricSigningKey
                },
                ApuSender = "SenderInfo",
                ApvSender = "ReceivererInfo"
            };

            var epkJObject = new JObject();
            epkJObject.Add(JsonWebKeyParameterNames.Kty, testData.PublicKeySender.Kty);
            epkJObject.Add(JsonWebKeyParameterNames.Crv, testData.PublicKeySender.Crv);
            epkJObject.Add(JsonWebKeyParameterNames.X, testData.PublicKeySender.X);
            epkJObject.Add(JsonWebKeyParameterNames.Y, testData.PublicKeySender.Y);
            testData.AdditionalHeaderParams = new Dictionary<string, object>();
            testData.AdditionalHeaderParams.Add(JwtHeaderParameterNames.Apu, testData.ApuSender);
            testData.AdditionalHeaderParams.Add(JwtHeaderParameterNames.Apv, testData.ApvSender);
            //testData.AdditionalHeaderParams.Add(JwtHeaderParameterNames.Epk, testData.PublicKeySender);
            testData.AdditionalHeaderParams.Add(JwtHeaderParameterNames.Epk, epkJObject);
            // APU, APV different
            return testData;
        }

        private static CreateEcdhEsTheoryData EcdhEsCurveP512EncA256KW()
        {
            // use of 521 is actually 512
            CreateEcdhEsTheoryData testData = new CreateEcdhEsTheoryData("EcdhEsCurveP512EncA256KW")
            {
                EncryptingCredentials = new EncryptingCredentials(
                                    new ECDsaSecurityKey(KeyingMaterial.JsonWebKeyP521, true),
                                    SecurityAlgorithms.EcdhEsA256kw,
                                    SecurityAlgorithms.Aes128CbcHmacSha256)
                {
                    KeyExchangePublicKey = KeyingMaterial.JsonWebKeyP521_Public
                },
                PublicKeyReceiver = KeyingMaterial.JsonWebKeyP521_Public,
                PublicKeySender = KeyingMaterial.JsonWebKeyP521_Public,
                PrivateKeyReceiver = KeyingMaterial.JsonWebKeyP521,
                TokenValidationParameters = new TokenValidationParameters()
                {
                    TokenDecryptionKey = new ECDsaSecurityKey(KeyingMaterial.JsonWebKeyP521, true),
                    ValidAudience = Default.Audience,
                    ValidIssuer = Default.Issuer,
                    IssuerSigningKey = Default.AsymmetricSigningKey
                },
                ApuSender = "SenderInfo",
                ApvSender = "ReceivererInfo"
            };

            var epkJObject = new JObject();
            epkJObject.Add(JsonWebKeyParameterNames.Kty, testData.PublicKeySender.Kty);
            epkJObject.Add(JsonWebKeyParameterNames.Crv, testData.PublicKeySender.Crv);
            epkJObject.Add(JsonWebKeyParameterNames.X, testData.PublicKeySender.X);
            epkJObject.Add(JsonWebKeyParameterNames.Y, testData.PublicKeySender.Y);
            testData.AdditionalHeaderParams = new Dictionary<string, object>();
            testData.AdditionalHeaderParams.Add(JwtHeaderParameterNames.Apu, testData.ApuSender);
            testData.AdditionalHeaderParams.Add(JwtHeaderParameterNames.Apv, testData.ApvSender);
            testData.AdditionalHeaderParams.Add(JwtHeaderParameterNames.Epk, epkJObject);

            return testData;
        }

        private static CreateEcdhEsTheoryData EcdhEsCurveP256EncA192KW()
        {
            CreateEcdhEsTheoryData testData = new CreateEcdhEsTheoryData("EcdhEsCurveP256EncA192KW")
            {
                EncryptingCredentials = new EncryptingCredentials(
                                    new ECDsaSecurityKey(KeyingMaterial.JsonWebKeyP256, true),
                                    SecurityAlgorithms.EcdhEsA192kw,
                                    SecurityAlgorithms.Aes192CbcHmacSha384)
                {
                    KeyExchangePublicKey = KeyingMaterial.JsonWebKeyP256_Public
                },
                PublicKeyReceiver = KeyingMaterial.JsonWebKeyP256_Public,
                PublicKeySender = KeyingMaterial.JsonWebKeyP256_Public,
                PrivateKeyReceiver = KeyingMaterial.JsonWebKeyP256,
                TokenValidationParameters = new TokenValidationParameters()
                {
                    TokenDecryptionKey = new ECDsaSecurityKey(KeyingMaterial.JsonWebKeyP256, true),
                    ValidAudience = Default.Audience,
                    ValidIssuer = Default.Issuer,
                    IssuerSigningKey = Default.AsymmetricSigningKey
                },
                ApuSender = "SenderInfo",
                ApvSender = "ReceivererInfo"
            };

            var epkJObject = new JObject();
            epkJObject.Add(JsonWebKeyParameterNames.Kty, testData.PublicKeySender.Kty);
            epkJObject.Add(JsonWebKeyParameterNames.Crv, testData.PublicKeySender.Crv);
            epkJObject.Add(JsonWebKeyParameterNames.X, testData.PublicKeySender.X);
            epkJObject.Add(JsonWebKeyParameterNames.Y, testData.PublicKeySender.Y);
            testData.AdditionalHeaderParams = new Dictionary<string, object>();
            testData.AdditionalHeaderParams.Add(JwtHeaderParameterNames.Apu, testData.ApuSender);
            testData.AdditionalHeaderParams.Add(JwtHeaderParameterNames.Apv, testData.ApvSender);
            testData.AdditionalHeaderParams.Add(JwtHeaderParameterNames.Epk, epkJObject);

            return testData;
        }

        private static CreateEcdhEsTheoryData EcdhEsCurveP256EncA128KW()
        {
            CreateEcdhEsTheoryData testData = new CreateEcdhEsTheoryData("EcdhEsCurveP256EncA128KW")
            {
                EncryptingCredentials = new EncryptingCredentials(
                                    new ECDsaSecurityKey(KeyingMaterial.JsonWebKeyP256, true),
                                    SecurityAlgorithms.EcdhEsA128kw,
                                    SecurityAlgorithms.Aes128CbcHmacSha256)
                {
                    KeyExchangePublicKey = KeyingMaterial.JsonWebKeyP256_Public
                },
                PublicKeyReceiver = KeyingMaterial.JsonWebKeyP256_Public,
                PublicKeySender = KeyingMaterial.JsonWebKeyP256_Public,
                PrivateKeyReceiver = KeyingMaterial.JsonWebKeyP256,
                TokenValidationParameters = new TokenValidationParameters()
                {
                    TokenDecryptionKey = new ECDsaSecurityKey(KeyingMaterial.JsonWebKeyP256, true),
                    ValidAudience = Default.Audience,
                    ValidIssuer = Default.Issuer,
                    IssuerSigningKey = Default.AsymmetricSigningKey
                },
                ApuSender = "SenderInfo",
                ApvSender = "ReceivererInfo"
            };

            var epkJObject = new JObject();
            epkJObject.Add(JsonWebKeyParameterNames.Kty, testData.PublicKeySender.Kty);
            epkJObject.Add(JsonWebKeyParameterNames.Crv, testData.PublicKeySender.Crv);
            epkJObject.Add(JsonWebKeyParameterNames.X, testData.PublicKeySender.X);
            epkJObject.Add(JsonWebKeyParameterNames.Y, testData.PublicKeySender.Y);
            testData.AdditionalHeaderParams = new Dictionary<string, object>();
            testData.AdditionalHeaderParams.Add(JwtHeaderParameterNames.Apu, testData.ApuSender);
            testData.AdditionalHeaderParams.Add(JwtHeaderParameterNames.Apv, testData.ApvSender);
            testData.AdditionalHeaderParams.Add(JwtHeaderParameterNames.Epk, epkJObject);

            return testData;
        }
    }

    public class CreateEcdhEsTheoryData : TheoryDataBase
    {
        public CreateEcdhEsTheoryData(string testId)
        {
            TestId = testId;
        }

        public string ApuReceiver { get; set; }
        public string ApvReceiver { get; set; }
        public string ApuSender { get; set; }
        public string ApvSender { get; set; }
        public EncryptingCredentials EncryptingCredentials { get; set; }
        public JsonWebKey PrivateKeyReceiver { get; set; }
        public JsonWebKey PublicKeyReceiver { get; set; }
        public JsonWebKey PublicKeySender { get; set; }
        public TokenValidationParameters TokenValidationParameters { get; set; }
        public bool ExpectedIsValid { get; set; } = true;
        public IDictionary<string, object> AdditionalHeaderParams { get; set; }
    }
}

#pragma warning restore CS3016 // Arrays as attribute arguments is not CLS-compliant
#endif // !NET45
