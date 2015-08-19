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
using System.Collections.Generic;
using System.IdentityModel.Tokens;
using System.IdentityModel.Tokens.Jwt;
using System.IdentityModel.Tokens.Tests;
using System.Reflection;
using System.Security.Claims;
using System.Threading;
using Xunit;

namespace Microsoft.IdentityModel.Protocols.OpenIdConnect.Tests
{
    /// <summary>
    /// 
    /// </summary>
    public class OpenIdConnectProtocolValidatorTests
    {
        [Fact(DisplayName = "OpenIdConnectProtocolValidatorTests: GenerateNonce")]
        public void GenerateNonce()
        {
            List<string> errors = new List<string>();
            OpenIdConnectProtocolValidator protocolValidator = new OpenIdConnectProtocolValidator();
            string nonce = protocolValidator.GenerateNonce();
            int endOfTimestamp = nonce.IndexOf('.');
            if (endOfTimestamp == -1)
            {
                errors.Add("nonce does not have '.' seperator");
            }
            else
            {

            }
        }

        [Fact(DisplayName = "OpenIdConnectProtocolValidatorTests: GetSets, test covers defaults")]
        public void GetSets()
        {
            OpenIdConnectProtocolValidator validationParameters = new OpenIdConnectProtocolValidator();
            Type type = typeof(OpenIdConnectProtocolValidator);
            PropertyInfo[] properties = type.GetProperties();
            if (properties.Length != 9)
                Assert.True(true, "Number of properties has changed from 9 to: " + properties.Length + ", adjust tests");

            GetSetContext context =
                new GetSetContext
                {
                    PropertyNamesAndSetGetValue = new List<KeyValuePair<string, List<object>>>
                    {
                        new KeyValuePair<string, List<object>>("NonceLifetime", new List<object>{TimeSpan.FromMinutes(60), TimeSpan.FromMinutes(10), TimeSpan.FromMinutes(100)}),
                        new KeyValuePair<string, List<object>>("RequireAcr", new List<object>{false, true, false}),
                        new KeyValuePair<string, List<object>>("RequireAmr", new List<object>{false, true, false}),
                        new KeyValuePair<string, List<object>>("RequireAuthTime", new List<object>{false, true, false}),
                        new KeyValuePair<string, List<object>>("RequireAzp", new List<object>{false, true, false}),
                        new KeyValuePair<string, List<object>>("RequireNonce", new List<object>{true, false, true}),
                        new KeyValuePair<string, List<object>>("RequireSub", new List<object>{false, true, false}),
                        new KeyValuePair<string, List<object>>("RequireTimeStampInNonce", new List<object>{true, false, true}),
                    },
                    Object = validationParameters,
                };

            TestUtilities.GetSet(context);
            TestUtilities.AssertFailIfErrors("OpenIdConnectProtocolValidator_GetSets", context.Errors);

            ExpectedException ee = ExpectedException.ArgumentNullException();
            Assert.NotNull(validationParameters.HashAlgorithmMap);
            Assert.Equal(validationParameters.HashAlgorithmMap.Count, 9);

            ee = ExpectedException.ArgumentOutOfRangeException();
            try
            {
                validationParameters.NonceLifetime = TimeSpan.Zero;
                ee.ProcessNoException();
            }
            catch (Exception ex)
            {
                ee.ProcessException(ex);
            }
        }

        [Fact(DisplayName = "OpenIdConnectProtocolValidatorTests: Validate")]
        public void Validate()
        {
            JwtSecurityToken jwt =  new JwtSecurityToken();
            OpenIdConnectProtocolValidationContext validationContext = new OpenIdConnectProtocolValidationContext();
            OpenIdConnectProtocolValidator protocolValidator = new OpenIdConnectProtocolValidator();

            // jwt null
            Validate(jwt: null, protocolValidator: protocolValidator, validationContext: null, ee: ExpectedException.ArgumentNullException());

            // validationContext null
            Validate(jwt: jwt, protocolValidator: protocolValidator, validationContext: null, ee: ExpectedException.ArgumentNullException());

            // aud missing
            Validate(jwt: jwt, protocolValidator: protocolValidator, validationContext: validationContext, ee: new ExpectedException(typeExpected: typeof(OpenIdConnectProtocolException), substringExpected: "IDX10309:"));

            // exp missing
            jwt.Payload.AddClaim(new Claim(JwtRegisteredClaimNames.Aud, IdentityUtilities.DefaultAudience));
            Validate(jwt: jwt, protocolValidator: protocolValidator, validationContext: validationContext, ee: new ExpectedException(typeExpected: typeof(OpenIdConnectProtocolException), substringExpected: "IDX10309:"));

            // iat missing
            jwt.Payload.AddClaim(new Claim(JwtRegisteredClaimNames.Exp, EpochTime.GetIntDate(DateTime.UtcNow).ToString()));
            Validate(jwt: jwt, protocolValidator: protocolValidator, validationContext: validationContext, ee: new ExpectedException(typeExpected: typeof(OpenIdConnectProtocolException), substringExpected: "IDX10309:"));

            // iss missing
            jwt.Payload.AddClaim(new Claim(JwtRegisteredClaimNames.Iat, EpochTime.GetIntDate(DateTime.UtcNow).ToString()));
            Validate(jwt: jwt, protocolValidator: protocolValidator, validationContext: validationContext, ee: new ExpectedException(typeExpected: typeof(OpenIdConnectProtocolException), substringExpected: "IDX10309:"));

            // add iis, nonce is not required, missing state
            protocolValidator.RequireNonce = false;
            jwt.Payload.AddClaim(new Claim(JwtRegisteredClaimNames.Iss, IdentityUtilities.DefaultIssuer));
            Validate(jwt: jwt, protocolValidator: protocolValidator, validationContext: validationContext, ee: new ExpectedException(typeExpected: typeof(OpenIdConnectProtocolInvalidStateException), substringExpected: "IDX10332:"));

            protocolValidator.RequireState = false;
            Validate(jwt: jwt, protocolValidator: protocolValidator, validationContext: validationContext, ee: ExpectedException.NoExceptionExpected);

            protocolValidator.RequireState = true;

            // add validState
            var state1 = Guid.NewGuid().ToString();
            var state2 = Guid.NewGuid().ToString();
            validationContext.State = state1;
            validationContext.ProtocolMessage = new OpenIdConnectMessage
            {
                State = state2,
            };

            // invalid state
            Validate(jwt: jwt, protocolValidator: protocolValidator, validationContext: validationContext, ee: new ExpectedException(typeExpected: typeof(OpenIdConnectProtocolInvalidStateException), substringExpected: "IDX10328:"));

            // valid state
            validationContext.ProtocolMessage.State = state1;
            Validate(jwt: jwt, protocolValidator: protocolValidator, validationContext: validationContext, ee: ExpectedException.NoExceptionExpected);

            // nonce invalid 
            string validNonce = protocolValidator.GenerateNonce();

            // add the valid 'nonce' but set validationContext.Nonce to a different 'nonce'.
            protocolValidator.RequireNonce = true;
            jwt.Payload.AddClaim(new Claim(JwtRegisteredClaimNames.Nonce, validNonce));
            validationContext.Nonce = protocolValidator.GenerateNonce();
            Validate(jwt: jwt, protocolValidator: protocolValidator, validationContext: validationContext, ee: new ExpectedException(typeExpected: typeof(OpenIdConnectProtocolInvalidNonceException), substringExpected: "IDX10301:"));

            // sub missing, default not required
            validationContext.Nonce = validNonce;
            Validate(jwt: jwt, protocolValidator: protocolValidator, validationContext: validationContext, ee: ExpectedException.NoExceptionExpected);

            protocolValidator.RequireSub = true;
            Validate(jwt: jwt, protocolValidator: protocolValidator, validationContext: validationContext, ee: new ExpectedException(typeExpected: typeof(OpenIdConnectProtocolException), substringExpected: "IDX10309:"));

            // authorizationCode invalid
            string validAuthorizationCode = protocolValidator.GenerateNonce();
            string validChash = IdentityUtilities.CreateHashClaim(validAuthorizationCode, "SHA256");

            JwtSecurityToken jwtWithSignatureChash =
                new JwtSecurityToken
                (
                    audience: IdentityUtilities.DefaultAudience,
                    claims: new List<Claim> 
                    { 
                        new Claim(JwtRegisteredClaimNames.CHash, validChash),
                        new Claim(JwtRegisteredClaimNames.Iat, EpochTime.GetIntDate(DateTime.UtcNow).ToString()),
                        new Claim(JwtRegisteredClaimNames.Nonce, validNonce),
                        new Claim(JwtRegisteredClaimNames.Sub, "sub"),
                    },
                    expires: DateTime.UtcNow + TimeSpan.FromHours(1),
                    issuer: IdentityUtilities.DefaultIssuer,
                    signingCredentials: IdentityUtilities.DefaultAsymmetricSigningCredentials
                );

            Dictionary<string,string> algmap = new Dictionary<string,string>(protocolValidator.HashAlgorithmMap);
            protocolValidator.HashAlgorithmMap.Clear();
            protocolValidator.HashAlgorithmMap.Add(JwtAlgorithms.RSA_SHA256, "SHA256");

            validationContext.Nonce = validNonce;

            // temporary till beta8
            validationContext.AuthorizationCode = validNonce;
            validationContext.ProtocolMessage.Code = validNonce;
            Validate(jwt: jwtWithSignatureChash, protocolValidator: protocolValidator, validationContext: validationContext, ee: new ExpectedException(typeExpected: typeof(OpenIdConnectProtocolInvalidCHashException), substringExpected: "IDX10329:", innerTypeExpected: typeof(OpenIdConnectProtocolException)));

            // nonce and authorizationCode valid
            validationContext.ProtocolMessage.Code = validAuthorizationCode;

            //temparary till beta8
            validationContext.AuthorizationCode = validAuthorizationCode;
            Validate(jwt: jwtWithSignatureChash, protocolValidator: protocolValidator, validationContext: validationContext, ee: ExpectedException.NoExceptionExpected);

            // validate optional claims
            protocolValidator.RequireAcr = true;
            Validate(jwt: jwtWithSignatureChash, protocolValidator: protocolValidator, validationContext: validationContext, ee: new ExpectedException(typeExpected: typeof(OpenIdConnectProtocolException), substringExpected: "IDX10312:"));
            jwtWithSignatureChash.Payload.AddClaim(new Claim(JwtRegisteredClaimNames.Acr, "acr"));

            protocolValidator.RequireAmr = true;
            Validate(jwt: jwtWithSignatureChash, protocolValidator: protocolValidator, validationContext: validationContext, ee: new ExpectedException(typeExpected: typeof(OpenIdConnectProtocolException), substringExpected: "IDX10313:"));
            jwtWithSignatureChash.Payload.AddClaim(new Claim(JwtRegisteredClaimNames.Amr, "amr"));

            protocolValidator.RequireAuthTime = true;
            Validate(jwt: jwtWithSignatureChash, protocolValidator: protocolValidator, validationContext: validationContext, ee: new ExpectedException(typeExpected: typeof(OpenIdConnectProtocolException), substringExpected: "IDX10314:"));
            jwtWithSignatureChash.Payload.AddClaim(new Claim(JwtRegisteredClaimNames.AuthTime, "authTime"));

            protocolValidator.RequireAzp = true;
            Validate(jwt: jwtWithSignatureChash, protocolValidator: protocolValidator, validationContext: validationContext, ee: new ExpectedException(typeExpected: typeof(OpenIdConnectProtocolException), substringExpected: "IDX10315:"));
            jwtWithSignatureChash.Payload.AddClaim(new Claim(JwtRegisteredClaimNames.Azp, "azp"));

            Validate(jwt: jwtWithSignatureChash, protocolValidator: protocolValidator, validationContext: validationContext, ee: ExpectedException.NoExceptionExpected);

            validationContext.ProtocolMessage = new OpenIdConnectMessage
            {
                IdToken = Guid.NewGuid().ToString()
            };

            Validate(null, protocolValidator, validationContext, new ExpectedException(typeof(OpenIdConnectProtocolException), "IDX10331:"));
        }

        public void Validate(JwtSecurityToken jwt, OpenIdConnectProtocolValidator protocolValidator, OpenIdConnectProtocolValidationContext validationContext, ExpectedException ee)
        {
            try
            {
                if (validationContext != null)
                {
                    validationContext.IdToken = jwt;
                }
                protocolValidator.Validate(validationContext);
                ee.ProcessNoException();
            }
            catch (Exception ex)
            {
                ee.ProcessException(ex);
            }

            // temporary till beta8
            try
            {
                protocolValidator.Validate(jwt, validationContext);
                ee.ProcessNoException();
            }
            catch (Exception ex)
            {
                ee.ProcessException(ex);
            }

        }

        [Fact(DisplayName = "OpenIdConnectProtocolValidatorTests: Validation of CHash")]
        public void Validate_CHash()
        {
            PublicOpenIdConnectProtocolValidator protocolValidator = new PublicOpenIdConnectProtocolValidator();

            string authorizationCode1 = protocolValidator.GenerateNonce();
            string authorizationCode2 = protocolValidator.GenerateNonce();

            string chash1 = IdentityUtilities.CreateHashClaim(authorizationCode1, "SHA256");
            string chash2 = IdentityUtilities.CreateHashClaim(authorizationCode2, "SHA256");

            Dictionary<string, string> emptyDictionary = new Dictionary<string, string>();
            Dictionary<string, string> mappedDictionary = new Dictionary<string, string>(protocolValidator.HashAlgorithmMap);

            JwtSecurityToken jwtWithCHash1 =
                new JwtSecurityToken
                (
                    audience: IdentityUtilities.DefaultAudience,
                    claims: new List<Claim> { new Claim(JwtRegisteredClaimNames.CHash, chash1) },
                    issuer: IdentityUtilities.DefaultIssuer
                );

            JwtSecurityToken jwtWithEmptyCHash =
                new JwtSecurityToken
                (
                    audience: IdentityUtilities.DefaultAudience,
                    claims: new List<Claim> { new Claim(JwtRegisteredClaimNames.CHash, string.Empty) },
                    issuer: IdentityUtilities.DefaultIssuer,
                    signingCredentials: IdentityUtilities.DefaultAsymmetricSigningCredentials
                );

            JwtSecurityToken jwtWithoutCHash =
                new JwtSecurityToken
                (
                    audience: IdentityUtilities.DefaultAudience,
                    claims: new List<Claim> { new Claim(JwtRegisteredClaimNames.Nonce, chash2) },
                    issuer: IdentityUtilities.DefaultIssuer                    
                );

            JwtSecurityToken jwtWithSignatureChash1 = 
                new JwtSecurityToken
                (
                    audience : IdentityUtilities.DefaultAudience,
                    claims: new List<Claim> { new Claim(JwtRegisteredClaimNames.CHash, chash1) },
                    issuer: IdentityUtilities.DefaultIssuer,
                    signingCredentials : IdentityUtilities.DefaultAsymmetricSigningCredentials
                );

            JwtSecurityToken jwtWithSignatureMultipleChashes =
                new JwtSecurityToken
                (
                    audience: IdentityUtilities.DefaultAudience,
                    claims: new List<Claim> { new Claim(JwtRegisteredClaimNames.CHash, chash1), new Claim(JwtRegisteredClaimNames.CHash, chash2) },
                    issuer: IdentityUtilities.DefaultIssuer,
                    signingCredentials: IdentityUtilities.DefaultAsymmetricSigningCredentials
                );


            OpenIdConnectProtocolValidationContext validationContext = new OpenIdConnectProtocolValidationContext();
            validationContext.ProtocolMessage = new OpenIdConnectMessage
            {
                Code = authorizationCode2
            };

            // chash is not a string, but array
            ValidateCHash(jwt: jwtWithSignatureMultipleChashes, protocolValidator: protocolValidator, validationContext: validationContext, ee: new ExpectedException(typeExpected: typeof(OpenIdConnectProtocolInvalidCHashException), substringExpected: "IDX10326:"));

            // chash doesn't match
            ValidateCHash(jwt: jwtWithSignatureChash1, protocolValidator: protocolValidator, validationContext: validationContext, ee: new ExpectedException(typeExpected: typeof(OpenIdConnectProtocolInvalidCHashException), substringExpected: "IDX10329:", innerTypeExpected: typeof(OpenIdConnectProtocolException)));

            // use algorithm map
            validationContext.ProtocolMessage = new OpenIdConnectMessage
            {
                Code = authorizationCode1
            };

            ValidateCHash(jwt: jwtWithSignatureChash1, protocolValidator: protocolValidator, validationContext: validationContext, ee: ExpectedException.NoExceptionExpected);

            // Creation of algorithm failed, need to map.
            // protocolValidator.SetHashAlgorithmMap(emptyDictionary);
            // ValidateCHash(jwt: jwtWithSignatureChash1, protocolValidator: protocolValidator, validationContext: validationContext, ee: new ExpectedException(typeExpected: typeof(OpenIdConnectProtocolInvalidCHashException), substringExpected: "IDX10307:"));
            //protocolValidator.SetHashAlgorithmMap(mappedDictionary);

            ValidateCHash(jwt: null, protocolValidator: protocolValidator, validationContext: validationContext, ee: ExpectedException.NoExceptionExpected);
            ValidateCHash(jwt: jwtWithoutCHash, protocolValidator: protocolValidator, validationContext: validationContext, ee: new ExpectedException(typeExpected: typeof(OpenIdConnectProtocolInvalidCHashException), substringExpected: "IDX10308:"));
            ValidateCHash(jwt: jwtWithEmptyCHash, protocolValidator: protocolValidator, validationContext: validationContext, ee: new ExpectedException(typeExpected: typeof(OpenIdConnectProtocolInvalidCHashException), substringExpected: "IDX10329:", innerTypeExpected: typeof(OpenIdConnectProtocolException)));
            ValidateCHash(jwt: jwtWithCHash1, protocolValidator: protocolValidator, validationContext: validationContext, ee: new ExpectedException(typeExpected: typeof(OpenIdConnectProtocolInvalidCHashException), substringExpected: "IDX10329:", innerTypeExpected: typeof(OpenIdConnectProtocolException)));
            ValidateCHash(jwt: jwtWithoutCHash, protocolValidator: protocolValidator, validationContext: null, ee: ExpectedException.ArgumentNullException());

            // make sure default alg works.
            validationContext.ProtocolMessage.Code = authorizationCode1;
            jwtWithCHash1.Header.Remove("alg");
            ValidateCHash(jwt: jwtWithCHash1, protocolValidator: protocolValidator, validationContext: validationContext, ee: ExpectedException.NoExceptionExpected);
        }

        private void ValidateCHash(JwtSecurityToken jwt, OpenIdConnectProtocolValidationContext validationContext, PublicOpenIdConnectProtocolValidator protocolValidator, ExpectedException ee)
        {
            try
            {
                if (validationContext != null)
                {
                    validationContext.IdToken = jwt;
                }
                protocolValidator.PublicValidateCHash(validationContext);
                ee.ProcessNoException();
            }
            catch(Exception ex)
            {
                ee.ProcessException(ex);
            }

            return;
        }

        [Fact(DisplayName = "OpenIdConnectProtocolValidatorTests: Validation of Nonce")]
        public void Validate_Nonce()
        {
            PublicOpenIdConnectProtocolValidator protocolValidatorRequiresTimeStamp = new PublicOpenIdConnectProtocolValidator();
            string nonceWithTimeStamp = protocolValidatorRequiresTimeStamp.GenerateNonce();

            PublicOpenIdConnectProtocolValidator protocolValidatorDoesNotRequireTimeStamp = 
                new PublicOpenIdConnectProtocolValidator
                {
                    RequireTimeStampInNonce = false,
                };

             PublicOpenIdConnectProtocolValidator protocolValidatorDoesNotRequireNonce =
                new PublicOpenIdConnectProtocolValidator
                {
                    RequireNonce = false,
                };

            string nonceWithoutTimeStamp = protocolValidatorDoesNotRequireTimeStamp.GenerateNonce();
            string nonceBadTimeStamp = "abc.abc";
            string nonceTicksTooLarge = Int64.MaxValue.ToString() + "." + nonceWithoutTimeStamp;
            string nonceTicksTooSmall = Int64.MinValue.ToString() + "." + nonceWithoutTimeStamp;
            string nonceTicksNegative = ((Int64)(-1)).ToString() + "." + nonceWithoutTimeStamp;
            string nonceTicksZero = ((Int64)(0)).ToString() + "." + nonceWithoutTimeStamp;

            JwtSecurityToken jwtWithNonceWithTimeStamp = new JwtSecurityToken ( claims: new List<Claim> { new Claim(JwtRegisteredClaimNames.Nonce, nonceWithTimeStamp) });
            JwtSecurityToken jwtWithNonceWithoutTimeStamp = new JwtSecurityToken(claims: new List<Claim> { new Claim(JwtRegisteredClaimNames.Nonce, nonceWithoutTimeStamp) });
            JwtSecurityToken jwtWithNonceWithBadTimeStamp = new JwtSecurityToken(claims: new List<Claim> { new Claim(JwtRegisteredClaimNames.Nonce, nonceBadTimeStamp) });
            JwtSecurityToken jwtWithNonceTicksTooLarge = new JwtSecurityToken(claims: new List<Claim> { new Claim(JwtRegisteredClaimNames.Nonce, nonceTicksTooLarge) });
            JwtSecurityToken jwtWithNonceTicksTooSmall = new JwtSecurityToken(claims: new List<Claim> { new Claim(JwtRegisteredClaimNames.Nonce, nonceTicksTooSmall) });
            JwtSecurityToken jwtWithNonceTicksNegative = new JwtSecurityToken(claims: new List<Claim> { new Claim(JwtRegisteredClaimNames.Nonce, nonceTicksNegative) });
            JwtSecurityToken jwtWithNonceZero = new JwtSecurityToken(claims: new List<Claim> { new Claim(JwtRegisteredClaimNames.Nonce, nonceTicksZero) });
            JwtSecurityToken jwtWithoutNonce = new JwtSecurityToken(claims: new List<Claim> { new Claim(JwtRegisteredClaimNames.NameId, nonceWithTimeStamp) });
            JwtSecurityToken jwtWithNonceWhitespace = new JwtSecurityToken(claims: new List<Claim> { new Claim(JwtRegisteredClaimNames.Nonce, "") });

            OpenIdConnectProtocolValidationContext validationContext = new OpenIdConnectProtocolValidationContext();

            validationContext.Nonce = null;
            ValidateNonce(jwt: null, protocolValidator: protocolValidatorRequiresTimeStamp, validationContext: validationContext, ee: ExpectedException.NoExceptionExpected);
            ValidateNonce(jwt: jwtWithNonceWithTimeStamp, protocolValidator: protocolValidatorRequiresTimeStamp, validationContext: null, ee: ExpectedException.ArgumentNullException());

            // nonce is null, RequireNonce is true.
            ValidateNonce(jwt: jwtWithNonceWithTimeStamp, protocolValidator: protocolValidatorRequiresTimeStamp, validationContext: validationContext, ee:  new ExpectedException(typeof(OpenIdConnectProtocolInvalidNonceException), substringExpected: "IDX10311:"));

            validationContext.Nonce = nonceWithoutTimeStamp;
            ValidateNonce(jwt: jwtWithoutNonce, protocolValidator: protocolValidatorRequiresTimeStamp, validationContext: validationContext, ee: new ExpectedException(typeof(OpenIdConnectProtocolInvalidNonceException), substringExpected: "IDX10322:"));
            ValidateNonce(jwt: jwtWithNonceWhitespace, protocolValidator: protocolValidatorRequiresTimeStamp, validationContext: validationContext, ee: new ExpectedException(typeof(OpenIdConnectProtocolInvalidNonceException), substringExpected: "IDX10301:"));
            ValidateNonce(jwt: jwtWithNonceWithTimeStamp, protocolValidator: protocolValidatorRequiresTimeStamp, validationContext: validationContext, ee: new ExpectedException(typeof(OpenIdConnectProtocolInvalidNonceException), substringExpected: "IDX10301:"));

            validationContext.Nonce = nonceWithTimeStamp;
            ValidateNonce(jwt: jwtWithNonceWithTimeStamp, protocolValidator: protocolValidatorRequiresTimeStamp, validationContext: validationContext, ee: ExpectedException.NoExceptionExpected);

            // nonce expired
            validationContext.Nonce = nonceWithTimeStamp;
            protocolValidatorRequiresTimeStamp.NonceLifetime = TimeSpan.FromMilliseconds(10);
            Thread.Sleep(100);
            ValidateNonce(jwt: jwtWithNonceWithTimeStamp, protocolValidator: protocolValidatorRequiresTimeStamp, validationContext: validationContext, ee: new ExpectedException(typeof(OpenIdConnectProtocolInvalidNonceException)));

            // nonce missing timestamp, validator requires time stamp
            // 1. not well formed, no '.'
            validationContext.Nonce = nonceWithoutTimeStamp;
            protocolValidatorRequiresTimeStamp.NonceLifetime = TimeSpan.FromMinutes(10);
            ValidateNonce(jwt: jwtWithNonceWithoutTimeStamp, protocolValidator: protocolValidatorRequiresTimeStamp, validationContext: validationContext, ee: new ExpectedException(typeof(OpenIdConnectProtocolInvalidNonceException), substringExpected: "IDX10317:"));
            
            // 2. timestamp not well formed
            validationContext.Nonce = nonceBadTimeStamp;
            ValidateNonce(jwt: jwtWithNonceWithBadTimeStamp, protocolValidator: protocolValidatorRequiresTimeStamp, validationContext: validationContext, ee: new ExpectedException( typeExpected: typeof(OpenIdConnectProtocolInvalidNonceException), innerTypeExpected: typeof(FormatException), substringExpected: "IDX10318:"));

            // 3. timestamp not required
            validationContext.Nonce = nonceBadTimeStamp;
            ValidateNonce(jwt: jwtWithNonceWithBadTimeStamp, protocolValidator: protocolValidatorDoesNotRequireTimeStamp, validationContext: validationContext, ee: ExpectedException.NoExceptionExpected);

            // 4. ticks max value
            validationContext.Nonce = nonceTicksTooLarge;
            ValidateNonce(jwt: jwtWithNonceTicksTooLarge, protocolValidator: protocolValidatorRequiresTimeStamp, validationContext: validationContext, ee: new ExpectedException(typeExpected: typeof(OpenIdConnectProtocolInvalidNonceException), innerTypeExpected: typeof(ArgumentException), substringExpected: "IDX10320:"));

            // 5. ticks min value small
            validationContext.Nonce = nonceTicksTooSmall;
            ValidateNonce(jwt: jwtWithNonceTicksTooSmall, protocolValidator: protocolValidatorRequiresTimeStamp, validationContext: validationContext, ee: new ExpectedException(typeExpected: typeof(OpenIdConnectProtocolInvalidNonceException), substringExpected: "IDX10318:"));

            // 6. ticks negative
            validationContext.Nonce = nonceTicksNegative;
            ValidateNonce(jwt: jwtWithNonceTicksNegative, protocolValidator: protocolValidatorRequiresTimeStamp, validationContext: validationContext, ee: new ExpectedException(typeExpected: typeof(OpenIdConnectProtocolInvalidNonceException), substringExpected: "IDX10318:"));            

            // 7. ticks zero
            validationContext.Nonce = nonceTicksZero;
            ValidateNonce(jwt: jwtWithNonceZero, protocolValidator: protocolValidatorRequiresTimeStamp, validationContext: validationContext, ee: new ExpectedException(typeExpected: typeof(OpenIdConnectProtocolInvalidNonceException), substringExpected: "IDX10318:"));

            // require nonce false
            validationContext.Nonce = null;
            ValidateNonce(jwt: jwtWithNonceWithoutTimeStamp, protocolValidator: protocolValidatorDoesNotRequireNonce, validationContext: validationContext, ee: ExpectedException.NoExceptionExpected);

            // validationContext has nonce
            validationContext.Nonce = nonceWithTimeStamp;
            ValidateNonce(jwt: jwtWithoutNonce, protocolValidator: protocolValidatorDoesNotRequireNonce, validationContext: validationContext, ee: new ExpectedException(typeExpected: typeof(OpenIdConnectProtocolInvalidNonceException), substringExpected: "IDX10323:"));
        }

        private void ValidateNonce(JwtSecurityToken jwt, PublicOpenIdConnectProtocolValidator protocolValidator, OpenIdConnectProtocolValidationContext validationContext, ExpectedException ee)
        {
            try
            {
                if (validationContext != null)
                {
                    validationContext.IdToken = jwt;
                }
                protocolValidator.PublicValidateNonce(validationContext);
                ee.ProcessNoException();
            }
            catch(Exception ex)
            {
                ee.ProcessException(ex);
            }
        }

#pragma warning disable CS3016 // Arrays as attribute arguments is not CLS-compliant
        [Theory, MemberData("AtHashDataSet")]
#pragma warning restore CS3016 // Arrays as attribute arguments is not CLS-compliant
        public void Validate_AtHash(OpenIdConnectProtocolValidationContext context, PublicOpenIdConnectProtocolValidator validator, ExpectedException ee)
        {
            try
            {
                validator.PublicValidateAtHash(context);
                ee.ProcessNoException();
            }
            catch(Exception ex)
            {
                ee.ProcessException(ex);
            }
        }

        public static TheoryData<OpenIdConnectProtocolValidationContext, PublicOpenIdConnectProtocolValidator, ExpectedException> AtHashDataSet
        {
            get
            {
                var dataset = new TheoryData<OpenIdConnectProtocolValidationContext, PublicOpenIdConnectProtocolValidator, ExpectedException>();
                var validator = new PublicOpenIdConnectProtocolValidator();
                var token = Guid.NewGuid().ToString();
                var hashClaimValue256 = IdentityUtilities.CreateHashClaim(token, "SHA256");
                var hashClaimValue512 = IdentityUtilities.CreateHashClaim(token, "SHA512");

                dataset.Add(
                    new OpenIdConnectProtocolValidationContext(),
                    validator,
                    ExpectedException.NoExceptionExpected
                );
                dataset.Add(
                    new OpenIdConnectProtocolValidationContext
                    {
                        IdToken = new JwtSecurityToken()
                    },
                    validator,
                    ExpectedException.NoExceptionExpected
                );
                dataset.Add(
                    new OpenIdConnectProtocolValidationContext()
                    {
                        ProtocolMessage = new OpenIdConnectMessage
                        {
                            IdToken = Guid.NewGuid().ToString(),
                            Token = token
                        }
                    },
                    validator,
                    new ExpectedException(typeof(OpenIdConnectProtocolInvalidAtHashException), "IDX10331:")
                );
                dataset.Add(
                    new OpenIdConnectProtocolValidationContext()
                    {
                        IdToken = new JwtSecurityToken
                        (
                            claims: new List<Claim> { new Claim("at_hash", hashClaimValue256) },
                            signingCredentials: IdentityUtilities.DefaultAsymmetricSigningCredentials
                        ),
                        ProtocolMessage = new OpenIdConnectMessage
                        {
                            Token = token,
                        }
                    },
                    validator,
                    ExpectedException.NoExceptionExpected
                );
                dataset.Add(
                    new OpenIdConnectProtocolValidationContext()
                    {
                        IdToken = new JwtSecurityToken
                        (
                            claims: new List<Claim> { new Claim("at_hash", hashClaimValue512) },
                            signingCredentials: IdentityUtilities.DefaultAsymmetricSigningCredentials
                        ),
                        ProtocolMessage = new OpenIdConnectMessage
                        {
                            Token = token,
                        }
                    },
                    validator,
                    new ExpectedException(typeof(OpenIdConnectProtocolInvalidAtHashException), "IDX10330:", typeof(OpenIdConnectProtocolException))
                );
                dataset.Add(
                    new OpenIdConnectProtocolValidationContext()
                    {
                        IdToken = new JwtSecurityToken
                        (
                            claims: new List<Claim> { new Claim("at_hash", hashClaimValue256) },
                            signingCredentials: IdentityUtilities.DefaultAsymmetricSigningCredentials
                        ),
                        ProtocolMessage = new OpenIdConnectMessage
                        {
                            Token = Guid.NewGuid().ToString(),
                        }
                    },
                    validator,
                    new ExpectedException(typeof(OpenIdConnectProtocolInvalidAtHashException), "IDX10330:", typeof(OpenIdConnectProtocolException))
                );
                dataset.Add(
                    new OpenIdConnectProtocolValidationContext()
                    {
                        IdToken = new JwtSecurityToken
                        (
                            claims: new List<Claim> { new Claim("at_hash", hashClaimValue256), new Claim("at_hash", hashClaimValue256) },
                            signingCredentials: IdentityUtilities.DefaultAsymmetricSigningCredentials
                        ),
                        ProtocolMessage = new OpenIdConnectMessage
                        {
                            Token = Guid.NewGuid().ToString(),
                        }
                    },
                    validator,
                    new ExpectedException(typeof(OpenIdConnectProtocolInvalidAtHashException), "IDX10325:")
                );

                return dataset;
            }
        }

#pragma warning disable CS3016 // Arrays as attribute arguments is not CLS-compliant
        [Theory, MemberData("StateDataSet")]
#pragma warning restore CS3016 // Arrays as attribute arguments is not CLS-compliant
        public void Validate_State(OpenIdConnectProtocolValidationContext context, PublicOpenIdConnectProtocolValidator validator, ExpectedException ee)
        {
            try
            {
                validator.PublicValidateState(context);
                ee.ProcessNoException();
            }
            catch (Exception ex)
            {
                ee.ProcessException(ex);
            }
        }

        public static TheoryData<OpenIdConnectProtocolValidationContext, PublicOpenIdConnectProtocolValidator, ExpectedException> StateDataSet
        {
            get
            {
                var dataset = new TheoryData<OpenIdConnectProtocolValidationContext, PublicOpenIdConnectProtocolValidator, ExpectedException>();
                var validator = new PublicOpenIdConnectProtocolValidator();
                var validatorRequireStateFalse = new PublicOpenIdConnectProtocolValidator { RequireState = false };
                var state1 = Guid.NewGuid().ToString();
                var state2 = Guid.NewGuid().ToString();

                dataset.Add(
                    new OpenIdConnectProtocolValidationContext(),
                    validator,
                    new ExpectedException(typeof(OpenIdConnectProtocolInvalidStateException), "IDX10332:")
                );
                dataset.Add(
                    new OpenIdConnectProtocolValidationContext(),
                    validatorRequireStateFalse,
                    ExpectedException.NoExceptionExpected
                );
                dataset.Add(
                    new OpenIdConnectProtocolValidationContext
                    {
                        State = state1,
                    },
                    validator,
                    new ExpectedException(typeof(OpenIdConnectProtocolInvalidStateException), "IDX10327:")
                );
                dataset.Add(
                    new OpenIdConnectProtocolValidationContext()
                    {
                        State = state1,
                        ProtocolMessage = new OpenIdConnectMessage
                        {
                            State = state1
                        }
                    },
                    validator,
                    ExpectedException.NoExceptionExpected
                );
                dataset.Add(
                    new OpenIdConnectProtocolValidationContext()
                    {
                        State = state1,
                        ProtocolMessage = new OpenIdConnectMessage
                        {
                            State = state2
                        }
                    },
                    validator,
                    new ExpectedException(typeof(OpenIdConnectProtocolInvalidStateException), "IDX10328:")
                );
                return dataset;
            }
        }
    }

    public class PublicOpenIdConnectProtocolValidator : OpenIdConnectProtocolValidator
    {
        public void PublicValidateCHash(OpenIdConnectProtocolValidationContext context)
        {
            base.ValidateCHash(context);
        }

        public void PublicValidateAtHash(OpenIdConnectProtocolValidationContext context)
        {
            base.ValidateAtHash(context);
        }

        public void PublicValidateNonce(OpenIdConnectProtocolValidationContext context)
        {
            base.ValidateNonce(context);
        }

        public void PublicValidateState(OpenIdConnectProtocolValidationContext context)
        {
            base.ValidateState(context);
        }

        public void SetHashAlgorithmMap(Dictionary<string, string> hashAlgorithmMap)
        {
            HashAlgorithmMap.Clear();
            foreach (var key in hashAlgorithmMap.Keys)
                HashAlgorithmMap.Add(key, hashAlgorithmMap[key]);
        }
    }
}
