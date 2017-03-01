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
using System.Collections.Generic;
using System.Diagnostics.Tracing;
using System.Globalization;
using System.IdentityModel.Tokens.Jwt;
using System.Reflection;
using System.Security.Claims;
using System.Security.Cryptography;
using System.Text;
using Microsoft.IdentityModel.Tokens;
using Microsoft.IdentityModel.Tokens.Tests;
using Newtonsoft.Json;
using Xunit;

namespace Microsoft.IdentityModel.Protocols.OpenIdConnect.Tests
{
    /// <summary>
    /// Tests for OpenIdConnectProtocolValidator
    /// </summary>
    public class OpenIdConnectProtocolValidatorTests
    {
        [Fact]
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

        [Fact]
        public void GetSets()
        {
            OpenIdConnectProtocolValidator validationParameters = new OpenIdConnectProtocolValidator();
            Type type = typeof(OpenIdConnectProtocolValidator);
            PropertyInfo[] properties = type.GetProperties();
            if (properties.Length != 10)
                Assert.True(true, "Number of properties has changed from 10 to: " + properties.Length + ", adjust tests");

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
                        new KeyValuePair<string, List<object>>("RequireSub", new List<object>{true, false, true}),
                        new KeyValuePair<string, List<object>>("RequireTimeStampInNonce", new List<object>{true, false, true}),
                        new KeyValuePair<string, List<object>>("RequireState", new List<object>{true, false, true}),
                        new KeyValuePair<string, List<object>>("RequireStateValidation", new List<object>{true, false, true}),
                    },
                    Object = validationParameters,
                };

            TestUtilities.GetSet(context);
            TestUtilities.AssertFailIfErrors("OpenIdConnectProtocolValidator_GetSets", context.Errors);

            ExpectedException ee = ExpectedException.ArgumentNullException();
            Assert.NotNull(validationParameters.HashAlgorithmMap);
            Assert.Equal(validationParameters.HashAlgorithmMap.Count, 18);

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

            ee = ExpectedException.ArgumentNullException();
            try
            {
                validationParameters.CryptoProviderFactory = null;
                ee.ProcessNoException();
            }
            catch (Exception ex)
            {
                ee.ProcessException(ex);
            }

        }

        private void ValidateAuthenticationResponse(OpenIdConnectProtocolValidationContext context, OpenIdConnectProtocolValidator validator, ExpectedException ee)
        {
            try
            {
                validator.ValidateAuthenticationResponse(context);
                ee.ProcessNoException();
            }
            catch (Exception ex)
            {
                ee.ProcessException(ex);
            }
        }

        private void ValidateTokenResponse(OpenIdConnectProtocolValidationContext context, OpenIdConnectProtocolValidator validator, ExpectedException ee)
        {
            try
            {
                validator.ValidateTokenResponse(context);
                ee.ProcessNoException();
            }
            catch (Exception ex)
            {
                ee.ProcessException(ex);
            }
        }

        private void ValidateUserInfoResponse(OpenIdConnectProtocolValidationContext context, OpenIdConnectProtocolValidator validator, ExpectedException ee)
        {
            try
            {
                validator.ValidateUserInfoResponse(context);
                ee.ProcessNoException();
            }
            catch (Exception ex)
            {
                ee.ProcessException(ex);
            }
        }

        [Fact]
        public void ValidateUserInfoResponse()
        {
            var protocolValidator = new OpenIdConnectProtocolValidator
            {
                RequireTimeStampInNonce = false,
                RequireStateValidation = false,
                RequireNonce = false
            };
            var validator = new PublicOpenIdConnectProtocolValidator { RequireState = false };
            var jwtWithNoSub = CreateValidatedIdToken();
            jwtWithNoSub.Payload.Remove(JwtRegisteredClaimNames.Sub);
            var jwtWithSub = CreateValidatedIdToken();
            var stringJwt = new JwtSecurityTokenHandler().WriteToken(jwtWithSub);

            var userInfoResponseJson = @"{ ""sub"": ""sub""}";
            var userInfoResponseJsonInvalidSub = @"{ ""sub"": ""sub1""}";
            var userInfoResponseJson2 = @"{ ""tid"":""cdc690f9 - b6b8 - 4023 - 813a - bae7143d1f87"",""oid"":""991fb93e - 7400 - 47aa - bdaa - a5f5ea6b5669"",""upn"":""testuser @Tratcheroutlook.onmicrosoft.com"",""sub"":""sub"",""given_name"":""test"",""family_name"":""user"",""name"":""test user""}";
            var userInfoResponseJsonWithNoSub = @"{ ""tid"":""cdc690f9 - b6b8 - 4023 - 813a - bae7143d1f87"",""oid"":""991fb93e - 7400 - 47aa - bdaa - a5f5ea6b5669"",""upn"":""testuser @Tratcheroutlook.onmicrosoft.com"",""given_name"":""test"",""family_name"":""user"",""name"":""test user""}";
            var protocolValidationContext = new OpenIdConnectProtocolValidationContext();

            // validationContext is null
            ValidateUserInfoResponse(null, validator, ExpectedException.ArgumentNullException());

            // validationContext.UserInfoEndpointResponse is null
            ValidateUserInfoResponse(
                protocolValidationContext,
                validator,
                new ExpectedException(typeof(OpenIdConnectProtocolException), "IDX10337:")
                );

            // validationContext.validatedIdToken is null
            protocolValidationContext.UserInfoEndpointResponse = "response";
            ValidateUserInfoResponse(
                protocolValidationContext,
                validator,
                new ExpectedException(typeof(OpenIdConnectProtocolException), "IDX10332:")
                );

            // invalid userinfo response
            protocolValidationContext.ValidatedIdToken = jwtWithSub;
            ValidateUserInfoResponse(
                protocolValidationContext,
                validator,
                new ExpectedException(typeof(OpenIdConnectProtocolException), "IDX10343:", typeof(JsonReaderException))
                );

            // 'sub' missing in userinfo response
            protocolValidationContext.UserInfoEndpointResponse = userInfoResponseJsonWithNoSub;
            ValidateUserInfoResponse(
                protocolValidationContext,
                validator,
                new ExpectedException(typeof(OpenIdConnectProtocolException), "IDX10345:")
                );

            // 'sub' missing in validated jwt token
            protocolValidationContext.UserInfoEndpointResponse = userInfoResponseJson2;
            protocolValidationContext.ValidatedIdToken = jwtWithNoSub;
            ValidateUserInfoResponse(
                protocolValidationContext,
                validator,
                new ExpectedException(typeof(OpenIdConnectProtocolException), "IDX10346:")
                );

            // unmatching "sub" claim
            protocolValidationContext.UserInfoEndpointResponse = userInfoResponseJsonInvalidSub;
            protocolValidationContext.ValidatedIdToken = jwtWithSub;
            ValidateUserInfoResponse(
                protocolValidationContext,
                validator,
                new ExpectedException(typeof(OpenIdConnectProtocolException), "IDX10338:")
                );

            // validation passes
            protocolValidationContext.UserInfoEndpointResponse = userInfoResponseJson;
            ValidateUserInfoResponse(protocolValidationContext, validator, ExpectedException.NoExceptionExpected);
            protocolValidationContext.UserInfoEndpointResponse = stringJwt;
            ValidateUserInfoResponse(protocolValidationContext, validator, ExpectedException.NoExceptionExpected);
            protocolValidationContext.UserInfoEndpointResponse = userInfoResponseJson2;
            ValidateUserInfoResponse(protocolValidationContext, validator, ExpectedException.NoExceptionExpected);
        }


        [Fact]
        public void ValidateMessageWithIdToken()
        {
            var protocolValidator = new OpenIdConnectProtocolValidator { RequireTimeStampInNonce = false };
            var validState = Guid.NewGuid().ToString();
            var validNonce = Guid.NewGuid().ToString();
            var jwt = CreateValidatedIdToken();
            jwt.Payload.AddClaim(new Claim(JwtRegisteredClaimNames.Nonce, validNonce));

            var protocolValidationContext = new OpenIdConnectProtocolValidationContext
            {
                ValidatedIdToken = jwt,
                ProtocolMessage = new OpenIdConnectMessage
                {
                    IdToken = Guid.NewGuid().ToString(),
                    State = validState,
                },
                Nonce = validNonce,
                State = validState
            };

            ValidateAuthenticationResponse(protocolValidationContext, protocolValidator, ExpectedException.NoExceptionExpected);

            // no 'access_token' in the message
            ValidateTokenResponse(
                protocolValidationContext,
                protocolValidator,
                new ExpectedException(typeof(OpenIdConnectProtocolException), "IDX10336:")
                );
        }

        [Fact]
        public void ValidateMessageWithIdTokenCode()
        {
            var protocolValidator = new OpenIdConnectProtocolValidator { RequireTimeStampInNonce = false };
            var validState = Guid.NewGuid().ToString();
            var validNonce = Guid.NewGuid().ToString();
            var validCode = Guid.NewGuid().ToString();
            var cHashClaim = IdentityUtilities.CreateHashClaim(validCode, "SHA256");
            var jwt = CreateValidatedIdToken();
            jwt.Payload.AddClaim(new Claim(JwtRegisteredClaimNames.Nonce, validNonce));
            jwt.Header[JwtHeaderParameterNames.Alg] = "RS256";

            var protocolValidationContext = new OpenIdConnectProtocolValidationContext
            {
                ValidatedIdToken = jwt,
                ProtocolMessage = new OpenIdConnectMessage
                {
                    IdToken = Guid.NewGuid().ToString(),
                    State = validState,
                    Code = validCode
                },
                Nonce = validNonce,
                State = validState
            };

            // code present, but no chash claim
            ValidateAuthenticationResponse(
                protocolValidationContext,
                protocolValidator,
                new ExpectedException(typeof(OpenIdConnectProtocolInvalidCHashException), "IDX10307:")
                );
            // no 'access_token' in the message
            ValidateTokenResponse(
                protocolValidationContext,
                protocolValidator,
                new ExpectedException(typeof(OpenIdConnectProtocolException), "IDX10336:")
                );

            // adding chash claim
            protocolValidationContext.ValidatedIdToken.Payload.AddClaim(new Claim(JwtRegisteredClaimNames.CHash, cHashClaim));
            ValidateAuthenticationResponse(protocolValidationContext, protocolValidator, ExpectedException.NoExceptionExpected);
            // no 'access_token' in the message
            ValidateTokenResponse(
                protocolValidationContext,
                protocolValidator,
                new ExpectedException(typeof(OpenIdConnectProtocolException), "IDX10336:")
                );
        }

        [Fact]
        public void ValidateMessageWithIdTokenCodeToken()
        {
            var protocolValidator = new OpenIdConnectProtocolValidator { RequireTimeStampInNonce = false };
            var validState = Guid.NewGuid().ToString();
            var validNonce = Guid.NewGuid().ToString();
            var validCode = Guid.NewGuid().ToString();
            var validAccessToken = Guid.NewGuid().ToString();
            var cHashClaim = IdentityUtilities.CreateHashClaim(validCode, "SHA256");
            var atHashClaim = IdentityUtilities.CreateHashClaim(validAccessToken, "SHA256");
            var jwt = CreateValidatedIdToken();
            jwt.Payload.AddClaim(new Claim(JwtRegisteredClaimNames.Nonce, validNonce));
            jwt.Payload.AddClaim(new Claim(JwtRegisteredClaimNames.CHash, cHashClaim));
            jwt.Header[JwtHeaderParameterNames.Alg] = "RS256";

            var protocolValidationContext = new OpenIdConnectProtocolValidationContext
            {
                ValidatedIdToken = jwt,
                ProtocolMessage = new OpenIdConnectMessage
                {
                    IdToken = Guid.NewGuid().ToString(),
                    State = validState,
                    Code = validCode,
                    AccessToken = validAccessToken
                },
                Nonce = validNonce,
                State = validState
            };

            // access_token present, but no atHash claim
            ValidateAuthenticationResponse(
                protocolValidationContext,
                protocolValidator,
                new ExpectedException(typeof(OpenIdConnectProtocolInvalidAtHashException), "IDX10312:")
                );
            // no exception since 'at_hash' claim is optional
            ValidateTokenResponse(protocolValidationContext, protocolValidator, ExpectedException.NoExceptionExpected);

            // adding atHash claim
            protocolValidationContext.ValidatedIdToken.Payload.AddClaim(new Claim(JwtRegisteredClaimNames.AtHash, atHashClaim));
            ValidateAuthenticationResponse(protocolValidationContext, protocolValidator, ExpectedException.NoExceptionExpected);
            ValidateTokenResponse(protocolValidationContext, protocolValidator, ExpectedException.NoExceptionExpected);
        }

        [Fact]
        public void ValidateMessageWithIdTokenToken()
        {
            var protocolValidator = new OpenIdConnectProtocolValidator { RequireTimeStampInNonce = false };
            var validState = Guid.NewGuid().ToString();
            var validNonce = Guid.NewGuid().ToString();
            var validAccessToken = Guid.NewGuid().ToString();
            var atHashClaim = IdentityUtilities.CreateHashClaim(validAccessToken, "SHA256");
            var jwt = CreateValidatedIdToken();
            jwt.Payload.AddClaim(new Claim(JwtRegisteredClaimNames.Nonce, validNonce));
            jwt.Header[JwtHeaderParameterNames.Alg] = "RS256";

            var protocolValidationContext = new OpenIdConnectProtocolValidationContext
            {
                ValidatedIdToken = jwt,
                ProtocolMessage = new OpenIdConnectMessage
                {
                    IdToken = Guid.NewGuid().ToString(),
                    State = validState,
                    AccessToken = validAccessToken
                },
                Nonce = validNonce,
                State = validState
            };

            // access_token present, but no atHash claim
            ValidateAuthenticationResponse(
                protocolValidationContext,
                protocolValidator,
                new ExpectedException(typeof(OpenIdConnectProtocolInvalidAtHashException), "IDX10312:")
                );
            // no exception since 'at_hash' claim is optional
            ValidateTokenResponse(protocolValidationContext, protocolValidator, ExpectedException.NoExceptionExpected);

            // adding atHash claim
            protocolValidationContext.ValidatedIdToken.Payload.AddClaim(new Claim(JwtRegisteredClaimNames.AtHash, atHashClaim));
            ValidateAuthenticationResponse(protocolValidationContext, protocolValidator, ExpectedException.NoExceptionExpected);
            ValidateTokenResponse(protocolValidationContext, protocolValidator, ExpectedException.NoExceptionExpected);
        }

        [Fact]
        public void ValidateMessageWithCode()
        {
            var protocolValidator = new OpenIdConnectProtocolValidator { RequireNonce = false };
            var validState = Guid.NewGuid().ToString();

            var protocolValidationContext = new OpenIdConnectProtocolValidationContext
            {
                ProtocolMessage = new OpenIdConnectMessage
                {
                    State = validState,
                    Code = Guid.NewGuid().ToString()
                }
            };

            // 'RequireState' is true but no state passed in validationContext
            ValidateAuthenticationResponse(
                protocolValidationContext,
                protocolValidator,
                new ExpectedException(typeof(OpenIdConnectProtocolInvalidStateException), "IDX10329:")
                );

            // turn off state validation but message.State is not null
            protocolValidator.RequireState = false;
            ValidateAuthenticationResponse(
                protocolValidationContext,
                protocolValidator,
                new ExpectedException(typeof(OpenIdConnectProtocolInvalidStateException), "IDX10329:")
                );

            // turn on state validation and add valid state
            protocolValidator.RequireState = true;
            protocolValidationContext.State = validState;
            ValidateAuthenticationResponse(protocolValidationContext, protocolValidator, ExpectedException.NoExceptionExpected);

            // absence of 'id_token' and 'access_token'
            ValidateTokenResponse(
                protocolValidationContext,
                protocolValidator,
                new ExpectedException(typeof(OpenIdConnectProtocolException), "IDX10336:")
                );
        }

        [Fact]
        public void ValidateMessageWithToken()
        {
            var protocolValidator = new OpenIdConnectProtocolValidator { RequireTimeStampInNonce = false };
            var validState = Guid.NewGuid().ToString();
            var validAccessToken = Guid.NewGuid().ToString();

            var protocolValidationContext = new OpenIdConnectProtocolValidationContext
            {
                ProtocolMessage = new OpenIdConnectMessage
                {
                    State = validState,
                    AccessToken = validAccessToken
                },
                State = validState
            };

            // access_token present, but no 'id_token'
            ValidateAuthenticationResponse(
                protocolValidationContext,
                protocolValidator,
                new ExpectedException(typeof(OpenIdConnectProtocolException), "IDX10334:")
                );
            ValidateTokenResponse(
                protocolValidationContext,
                protocolValidator,
                new ExpectedException(typeof(OpenIdConnectProtocolException), "IDX10336:")
                );
        }

        [Fact]
        public void ValidateMessageWithCodeToken()
        {
            var protocolValidator = new OpenIdConnectProtocolValidator { RequireTimeStampInNonce = false };
            var validState = Guid.NewGuid().ToString();
            var validCode = Guid.NewGuid().ToString();
            var validAccessToken = Guid.NewGuid().ToString();
            var cHashClaim = IdentityUtilities.CreateHashClaim(validCode, "SHA256");
            var atHashClaim = IdentityUtilities.CreateHashClaim(validAccessToken, "SHA256");

            var protocolValidationContext = new OpenIdConnectProtocolValidationContext
            {
                ProtocolMessage = new OpenIdConnectMessage
                {
                    State = validState,
                    Code = validCode,
                    AccessToken = validAccessToken
                },
                State = validState
            };

            // code present, but no 'id_token'
            ValidateAuthenticationResponse(protocolValidationContext, protocolValidator, ExpectedException.NoExceptionExpected);

            // 'code' and 'access_token' present but no 'id_token'
            ValidateTokenResponse(
                protocolValidationContext,
                protocolValidator,
                new ExpectedException(typeof(OpenIdConnectProtocolException), "IDX10336:")
                );
        }

        private JwtSecurityToken CreateValidatedIdToken()
        {
            var jwt = new JwtSecurityToken();
            jwt.Payload.AddClaim(new Claim(JwtRegisteredClaimNames.Aud, IdentityUtilities.DefaultAudience));
            jwt.Payload.AddClaim(new Claim(JwtRegisteredClaimNames.Exp, EpochTime.GetIntDate(DateTime.UtcNow).ToString()));
            jwt.Payload.AddClaim(new Claim(JwtRegisteredClaimNames.Iat, EpochTime.GetIntDate(DateTime.UtcNow).ToString()));
            jwt.Payload.AddClaim(new Claim(JwtRegisteredClaimNames.Iss, IdentityUtilities.DefaultIssuer));
            jwt.Payload.AddClaim(new Claim(JwtRegisteredClaimNames.Sub, "sub"));
            return jwt;
        }

        [Fact]
        public void ValidateAuthenticationResponse()
        {
            var validator = new PublicOpenIdConnectProtocolValidator { RequireState = false };
            var protocolValidationContext = new OpenIdConnectProtocolValidationContext
            {
                ProtocolMessage = new OpenIdConnectMessage()
            };

            // validationContext is null
            ValidateAuthenticationResponse(null, validator, ExpectedException.ArgumentNullException());

            // validationContext.ProtocolMessage is null
            ValidateAuthenticationResponse(
                new OpenIdConnectProtocolValidationContext(),
                validator,
                new ExpectedException(typeof(OpenIdConnectProtocolException), "IDX10333:")
                );

            // validationContext.ProtocolMessage.IdToken is null
            ValidateAuthenticationResponse(
                protocolValidationContext,
                validator,
                new ExpectedException(typeof(OpenIdConnectProtocolException), "IDX10334:")
                );

            // validationContext.ProtocolMessage.IdToken is not null, whereas validationContext.validatedIdToken is null
            protocolValidationContext.ProtocolMessage.IdToken = Guid.NewGuid().ToString();
            ValidateAuthenticationResponse(
                protocolValidationContext,
                validator,
                new ExpectedException(typeof(OpenIdConnectProtocolException), "IDX10332:")
                );

            // 'refresh_token' should not be present in the response received from Authorization Endpoint
            protocolValidationContext.ValidatedIdToken = new JwtSecurityToken();
            protocolValidationContext.ProtocolMessage.RefreshToken = "refresh_token";
            ValidateAuthenticationResponse(
                protocolValidationContext,
                validator,
                new ExpectedException(typeof(OpenIdConnectProtocolException), "IDX10335:")
                );
        }

        private void ValidateIdToken(JwtSecurityToken jwt, OpenIdConnectProtocolValidationContext validationContext, PublicOpenIdConnectProtocolValidator protocolValidator, ExpectedException ee)
        {
            try
            {
                protocolValidator.PublicValidateIdToken(jwt, validationContext);
                ee.ProcessNoException();
            }
            catch (Exception ex)
            {
                ee.ProcessException(ex);
            }

            return;
        }

        [Fact]
        public void ValidateIdToken()
        {
            var validator = new PublicOpenIdConnectProtocolValidator { RequireState = false };
            var protocolValidationContext = new OpenIdConnectProtocolValidationContext
            {
                ProtocolMessage = new OpenIdConnectMessage()
            };
            var validatedIdToken = new JwtSecurityToken();

            // aud missing
            ValidateIdToken(
                validatedIdToken,
                protocolValidationContext,
                validator,
                new ExpectedException(typeof(OpenIdConnectProtocolException), "IDX10314:")
                );

            // exp missing
            validatedIdToken.Payload.AddClaim(new Claim(JwtRegisteredClaimNames.Aud, IdentityUtilities.DefaultAudience));
            ValidateIdToken(
                validatedIdToken,
                protocolValidationContext,
                validator,
                new ExpectedException(typeof(OpenIdConnectProtocolException), "IDX10314:")
                );

            // iat missing
            validatedIdToken.Payload.AddClaim(new Claim(JwtRegisteredClaimNames.Exp, EpochTime.GetIntDate(DateTime.UtcNow).ToString()));
            ValidateIdToken(
                validatedIdToken,
                protocolValidationContext,
                validator,
                new ExpectedException(typeof(OpenIdConnectProtocolException), "IDX10314:")
                );

            // iss missing
            validatedIdToken.Payload.AddClaim(new Claim(JwtRegisteredClaimNames.Iat, EpochTime.GetIntDate(DateTime.UtcNow).ToString()));
            ValidateIdToken(
                validatedIdToken,
                protocolValidationContext,
                validator,
                new ExpectedException(typeof(OpenIdConnectProtocolException), "IDX10314:")
                );

            // add iss, nonce is not required, state not required, sub not required
            validator.RequireNonce = false;
            validator.RequireSub = false;
            validatedIdToken.Payload.AddClaim(new Claim(JwtRegisteredClaimNames.Iss, IdentityUtilities.DefaultIssuer));
            ValidateIdToken(validatedIdToken, protocolValidationContext, validator, ExpectedException.NoExceptionExpected);

            // missing 'sub'
            validator.RequireSub = true;
            ValidateIdToken(
                validatedIdToken,
                protocolValidationContext,
                validator,
                new ExpectedException(typeof(OpenIdConnectProtocolException), "IDX10314:")
                );
            validator.RequireSub = false;

            // validate optional claims, 'acr' claim
            validator.RequireAcr = true;
            ValidateIdToken(
                validatedIdToken,
                protocolValidationContext,
                validator,
                new ExpectedException(typeof(OpenIdConnectProtocolException), "IDX10315:")
                );
            validatedIdToken.Payload.AddClaim(new Claim(JwtRegisteredClaimNames.Acr, "acr"));

            // 'amr' claim
            validator.RequireAmr = true;
            ValidateIdToken(
                validatedIdToken,
                protocolValidationContext,
                validator,
                new ExpectedException(typeof(OpenIdConnectProtocolException), "IDX10316:")
                );
            validatedIdToken.Payload.AddClaim(new Claim(JwtRegisteredClaimNames.Amr, "amr"));

            // 'auth_time' claim
            validator.RequireAuthTime = true;
            ValidateIdToken(
                validatedIdToken,
                protocolValidationContext,
                validator,
                new ExpectedException(typeof(OpenIdConnectProtocolException), "IDX10317:")
                );
            validatedIdToken.Payload.AddClaim(new Claim(JwtRegisteredClaimNames.AuthTime, EpochTime.GetIntDate(DateTime.UtcNow).ToString()));

            // multiple 'aud' but no 'azp' claim. no exception thrown, warning logged
            validatedIdToken.Payload[JwtRegisteredClaimNames.Aud] = new List<string> { "abc", "xyz" };
            ValidateIdToken(validatedIdToken, protocolValidationContext, validator, ExpectedException.NoExceptionExpected);

            // 'azp' claim
            validator.RequireAzp = true;
            ValidateIdToken(
                validatedIdToken,
                protocolValidationContext,
                validator,
                new ExpectedException(typeof(OpenIdConnectProtocolException), "IDX10318:")
                );
            validatedIdToken.Payload.AddClaim(new Claim(JwtRegisteredClaimNames.Azp, "azp"));

            // 'azp' claim present but 'client_id' is null
            ValidateIdToken(
                validatedIdToken,
                protocolValidationContext,
                validator,
                new ExpectedException(typeof(OpenIdConnectProtocolException), "IDX10308:")
                );

            // 'azp' claim present but 'client_id' does not match
            protocolValidationContext.ClientId = "client_id";
            ValidateIdToken(
                validatedIdToken,
                protocolValidationContext,
                validator,
                new ExpectedException(typeof(OpenIdConnectProtocolException), "IDX10340:")
                );

            // all claims present, no exception expected
            protocolValidationContext.ClientId = "azp";
            ValidateIdToken(validatedIdToken, protocolValidationContext, validator, ExpectedException.NoExceptionExpected);

            // validating the delegate
            IdTokenValidator idTokenValidatorThrows = ((jwt, context) => { throw new InvalidOperationException("Validator"); });
            IdTokenValidator idTokenValidatorReturns = ((jwt, context) => { return; });
            IdTokenValidator idTokenValidatorValidateAcr =
                ((jwt, context) =>
                {
                    JwtSecurityToken jwtSecurityToken = jwt as JwtSecurityToken;
                    if (jwtSecurityToken.Payload.Acr != "acr")
                        throw new InvalidOperationException();
                });
            validator.IdTokenValidator = idTokenValidatorThrows;
            ValidateIdToken(
                validatedIdToken,
                protocolValidationContext,
                validator,
                new ExpectedException(typeof(OpenIdConnectProtocolException), "IDX10313:", typeof(InvalidOperationException))
                );

            validator.IdTokenValidator = idTokenValidatorReturns;
            ValidateIdToken(validatedIdToken, protocolValidationContext, validator, ExpectedException.NoExceptionExpected);

            validator.IdTokenValidator = idTokenValidatorValidateAcr;
            ValidateIdToken(validatedIdToken, protocolValidationContext, validator, ExpectedException.NoExceptionExpected);
        }

        private void ValidateCHash(JwtSecurityToken jwt, OpenIdConnectProtocolValidationContext validationContext, PublicOpenIdConnectProtocolValidator protocolValidator, ExpectedException ee)
        {
            try
            {
                protocolValidator.PublicValidateCHash(jwt, validationContext);
                ee.ProcessNoException();
            }
            catch (Exception ex)
            {
                ee.ProcessException(ex);
            }

            return;
        }

        [Fact]
        public void Validate_CHash()
        {
            var protocolValidator = new PublicOpenIdConnectProtocolValidator();

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
                    issuer: IdentityUtilities.DefaultIssuer
                );

            JwtSecurityToken jwtWithSignatureChash1 =
                new JwtSecurityToken
                (
                    audience: IdentityUtilities.DefaultAudience,
                    claims: new List<Claim> { new Claim(JwtRegisteredClaimNames.CHash, chash1) },
                    issuer: IdentityUtilities.DefaultIssuer,
                    signingCredentials: IdentityUtilities.DefaultAsymmetricSigningCredentials
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
            ValidateCHash(
                jwtWithSignatureMultipleChashes,
                validationContext,
                protocolValidator,
                new ExpectedException(typeof(OpenIdConnectProtocolInvalidCHashException), "IDX10306:")
                );

            // chash doesn't match
            ValidateCHash(
                jwtWithSignatureChash1,
                validationContext,
                protocolValidator,
                new ExpectedException(typeof(OpenIdConnectProtocolInvalidCHashException), "IDX10347:", typeof(OpenIdConnectProtocolException))
                );

            // valid code
            validationContext.ProtocolMessage = new OpenIdConnectMessage
            {
                Code = authorizationCode1
            };

            ValidateCHash(jwtWithSignatureChash1, validationContext, protocolValidator, ExpectedException.NoExceptionExpected);

            // 'id_token' is null
            ValidateCHash(null, validationContext, protocolValidator, ExpectedException.ArgumentNullException());
            // validationContext is null
            ValidateCHash(jwtWithoutCHash, null, protocolValidator, ExpectedException.ArgumentNullException());

            // 'c_hash' claim is not present
            ValidateCHash(
                jwtWithoutCHash,
                validationContext,
                protocolValidator,
                new ExpectedException(typeof(OpenIdConnectProtocolInvalidCHashException), "IDX10307:")
                );
            // empty 'c_hash' claim
            ValidateCHash(
                jwtWithEmptyCHash,
                validationContext,
                protocolValidator,
                new ExpectedException(typeof(OpenIdConnectProtocolInvalidCHashException), "IDX10347:", typeof(OpenIdConnectProtocolException))
                );
            // algorithm mismatch. header.alg is 'None'.
            ValidateCHash(
                jwtWithCHash1,
                validationContext,
                protocolValidator,
                new ExpectedException(typeof(OpenIdConnectProtocolInvalidCHashException), "IDX10347:", typeof(OpenIdConnectProtocolException))
                );

            // make sure default alg works.
            validationContext.ProtocolMessage.Code = authorizationCode1;
            jwtWithCHash1.Header.Remove("alg");
            ValidateCHash(jwtWithCHash1, validationContext, protocolValidator, ExpectedException.NoExceptionExpected);
        }

        private void ValidateNonce(JwtSecurityToken jwt, PublicOpenIdConnectProtocolValidator protocolValidator, OpenIdConnectProtocolValidationContext validationContext, ExpectedException ee)
        {
            try
            {
                protocolValidator.PublicValidateNonce(jwt, validationContext);
                ee.ProcessNoException();
            }
            catch (Exception ex)
            {
                ee.ProcessException(ex);
            }
        }

        [Fact]
        public void Validate_Nonce()
        {
            PublicOpenIdConnectProtocolValidator protocolValidatorRequiresTimeStamp = new PublicOpenIdConnectProtocolValidator();
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

            string nonceWithTimeStamp = protocolValidatorRequiresTimeStamp.GenerateNonce();
            string nonceWithoutTimeStamp = protocolValidatorDoesNotRequireTimeStamp.GenerateNonce();
            string nonceBadTimeStamp = "abc.abc";
            string nonceTicksTooLarge = Int64.MaxValue.ToString() + "." + nonceWithoutTimeStamp;
            string nonceTicksTooSmall = Int64.MinValue.ToString() + "." + nonceWithoutTimeStamp;
            string nonceTicksNegative = ((Int64)(-1)).ToString() + "." + nonceWithoutTimeStamp;
            string nonceTicksZero = ((Int64)(0)).ToString() + "." + nonceWithoutTimeStamp;
            string nonceExpired = (DateTime.UtcNow - TimeSpan.FromMinutes(20)).Ticks.ToString(CultureInfo.InvariantCulture) + "." + Convert.ToBase64String(Encoding.UTF8.GetBytes(Guid.NewGuid().ToString() + Guid.NewGuid().ToString()));

            JwtSecurityToken jwtWithNonceWithTimeStamp = new JwtSecurityToken(claims: new List<Claim> { new Claim(JwtRegisteredClaimNames.Nonce, nonceWithTimeStamp) });
            JwtSecurityToken jwtWithNonceExpired = new JwtSecurityToken(claims: new List<Claim> { new Claim(JwtRegisteredClaimNames.Nonce, nonceExpired) });
            JwtSecurityToken jwtWithNonceWithoutTimeStamp = new JwtSecurityToken(claims: new List<Claim> { new Claim(JwtRegisteredClaimNames.Nonce, nonceWithoutTimeStamp) });
            JwtSecurityToken jwtWithNonceWithBadTimeStamp = new JwtSecurityToken(claims: new List<Claim> { new Claim(JwtRegisteredClaimNames.Nonce, nonceBadTimeStamp) });
            JwtSecurityToken jwtWithNonceTicksTooLarge = new JwtSecurityToken(claims: new List<Claim> { new Claim(JwtRegisteredClaimNames.Nonce, nonceTicksTooLarge) });
            JwtSecurityToken jwtWithNonceTicksTooSmall = new JwtSecurityToken(claims: new List<Claim> { new Claim(JwtRegisteredClaimNames.Nonce, nonceTicksTooSmall) });
            JwtSecurityToken jwtWithNonceTicksNegative = new JwtSecurityToken(claims: new List<Claim> { new Claim(JwtRegisteredClaimNames.Nonce, nonceTicksNegative) });
            JwtSecurityToken jwtWithNonceZero = new JwtSecurityToken(claims: new List<Claim> { new Claim(JwtRegisteredClaimNames.Nonce, nonceTicksZero) });
            JwtSecurityToken jwtWithoutNonce = new JwtSecurityToken(claims: new List<Claim> { new Claim(JwtRegisteredClaimNames.NameId, nonceWithTimeStamp) });
            JwtSecurityToken jwtWithNonceWhitespace = new JwtSecurityToken(claims: new List<Claim> { new Claim(JwtRegisteredClaimNames.Nonce, " ") });

            OpenIdConnectProtocolValidationContext validationContext = new OpenIdConnectProtocolValidationContext();

            validationContext.Nonce = null;
            // id_token is null
            ValidateNonce(null, protocolValidatorRequiresTimeStamp, validationContext, ExpectedException.ArgumentNullException());
            // validationContext is null
            ValidateNonce(jwtWithNonceWithTimeStamp, protocolValidatorRequiresTimeStamp, null, ExpectedException.ArgumentNullException());
            // validationContext.nonce is null, RequireNonce is true.
            ValidateNonce(
                jwtWithNonceWithTimeStamp,
                protocolValidatorRequiresTimeStamp,
                validationContext,
                new ExpectedException(typeof(OpenIdConnectProtocolInvalidNonceException), "IDX10320:")
                );

            validationContext.Nonce = nonceWithoutTimeStamp;
            // idToken.nonce is null, validationContext.nonce is not null
            ValidateNonce(
                jwtWithoutNonce,
                protocolValidatorRequiresTimeStamp,
                validationContext,
                new ExpectedException(typeof(OpenIdConnectProtocolInvalidNonceException), "IDX10323:")
                );
            // nonce does not match
            ValidateNonce(
                jwtWithNonceWhitespace,
                protocolValidatorRequiresTimeStamp,
                validationContext,
                new ExpectedException(typeof(OpenIdConnectProtocolInvalidNonceException), "IDX10321:")
                );
            ValidateNonce(
                jwtWithNonceWithTimeStamp,
                protocolValidatorRequiresTimeStamp,
                validationContext,
                new ExpectedException(typeof(OpenIdConnectProtocolInvalidNonceException), "IDX10321:")
                );

            // nonce match
            validationContext.Nonce = nonceWithTimeStamp;
            ValidateNonce(jwtWithNonceWithTimeStamp, protocolValidatorRequiresTimeStamp, validationContext, ExpectedException.NoExceptionExpected);

            // nonce expired
            validationContext.Nonce = nonceExpired;
            protocolValidatorRequiresTimeStamp.NonceLifetime = TimeSpan.FromMilliseconds(10);
            ValidateNonce(
                jwtWithNonceExpired,
                protocolValidatorRequiresTimeStamp,
                validationContext,
                new ExpectedException(typeof(OpenIdConnectProtocolInvalidNonceException), "IDX10324: ")
                );

            // nonce missing timestamp, validator requires time stamp
            // 1. no time stamp
            validationContext.Nonce = nonceWithoutTimeStamp;
            protocolValidatorRequiresTimeStamp.NonceLifetime = TimeSpan.FromMinutes(10);
            ValidateNonce(
                jwtWithNonceWithoutTimeStamp,
                protocolValidatorRequiresTimeStamp,
                validationContext,
                new ExpectedException(typeof(OpenIdConnectProtocolInvalidNonceException), "IDX10325:")
                );

            // 2. timestamp not well formed
            validationContext.Nonce = nonceBadTimeStamp;
            ValidateNonce(
                jwtWithNonceWithBadTimeStamp,
                protocolValidatorRequiresTimeStamp,
                validationContext,
                new ExpectedException(typeof(OpenIdConnectProtocolInvalidNonceException), "IDX10326:", typeof(FormatException))
                );

            // 3. timestamp not required
            validationContext.Nonce = nonceBadTimeStamp;
            ValidateNonce(jwtWithNonceWithBadTimeStamp, protocolValidatorDoesNotRequireTimeStamp, validationContext, ExpectedException.NoExceptionExpected);

            // 4. ticks max value
            validationContext.Nonce = nonceTicksTooLarge;
            ValidateNonce(
                jwtWithNonceTicksTooLarge,
                protocolValidatorRequiresTimeStamp,
                validationContext,
                new ExpectedException(typeof(OpenIdConnectProtocolInvalidNonceException), "IDX10327:", typeof(ArgumentException))
                );

            // 5. ticks min value small
            validationContext.Nonce = nonceTicksTooSmall;
            ValidateNonce(
                jwtWithNonceTicksTooSmall,
                protocolValidatorRequiresTimeStamp,
                validationContext,
                new ExpectedException(typeof(OpenIdConnectProtocolInvalidNonceException), "IDX10326:")
                );

            // 6. ticks negative
            validationContext.Nonce = nonceTicksNegative;
            ValidateNonce(
                jwtWithNonceTicksNegative,
                protocolValidatorRequiresTimeStamp,
                validationContext,
                new ExpectedException(typeof(OpenIdConnectProtocolInvalidNonceException), "IDX10326:")
                );

            // 7. ticks zero
            validationContext.Nonce = nonceTicksZero;
            ValidateNonce(
                jwtWithNonceZero,
                protocolValidatorRequiresTimeStamp,
                validationContext,
                new ExpectedException(typeof(OpenIdConnectProtocolInvalidNonceException), "IDX10326:")
                );

            // validationcontext.nonce == null, idToken.nonce != null and requireNonce is false
            validationContext.Nonce = null;
            ValidateNonce(
                jwtWithNonceWithoutTimeStamp,
                protocolValidatorDoesNotRequireNonce,
                validationContext,
                new ExpectedException(typeof(OpenIdConnectProtocolInvalidNonceException), "IDX10320:")
                );

            // validationContext has nonce, idToken.nonce is null and requireNonce is false
            validationContext.Nonce = nonceWithTimeStamp;
            ValidateNonce(
                jwtWithoutNonce,
                protocolValidatorDoesNotRequireNonce,
                validationContext,
                new ExpectedException(typeof(OpenIdConnectProtocolInvalidNonceException), "IDX10323:")
                );
            // idToken.Nonce is not null
            ValidateNonce(jwtWithNonceWithTimeStamp, protocolValidatorDoesNotRequireNonce, validationContext, ExpectedException.NoExceptionExpected);

        }

#pragma warning disable CS3016 // Arrays as attribute arguments is not CLS-compliant
        [Theory, MemberData("AtHashDataSet")]
#pragma warning restore CS3016 // Arrays as attribute arguments is not CLS-compliant
        public void Validate_AtHash(JwtSecurityToken jwt, OpenIdConnectProtocolValidationContext context, PublicOpenIdConnectProtocolValidator validator, ExpectedException ee)
        {
            try
            {
                validator.PublicValidateAtHash(jwt, context);
                ee.ProcessNoException();
            }
            catch (Exception ex)
            {
                ee.ProcessException(ex);
            }
        }

        public static TheoryData<JwtSecurityToken, OpenIdConnectProtocolValidationContext, PublicOpenIdConnectProtocolValidator, ExpectedException> AtHashDataSet
        {
            get
            {
                var dataset = new TheoryData<JwtSecurityToken, OpenIdConnectProtocolValidationContext, PublicOpenIdConnectProtocolValidator, ExpectedException>();
                var validator = new PublicOpenIdConnectProtocolValidator();
                var token = Guid.NewGuid().ToString();
                var hashClaimValue256 = IdentityUtilities.CreateHashClaim(token, "SHA256");
                var hashClaimValue512 = IdentityUtilities.CreateHashClaim(token, "SHA512");

                dataset.Add(
                    null,
                    new OpenIdConnectProtocolValidationContext(),
                    validator,
                    new ExpectedException(typeof(ArgumentNullException))
                );
                dataset.Add(
                    new JwtSecurityToken(),
                    new OpenIdConnectProtocolValidationContext(),
                    validator,
                    new ExpectedException(typeof(OpenIdConnectProtocolException), "IDX10333:")
                );
                dataset.Add(
                    null,
                    new OpenIdConnectProtocolValidationContext()
                    {
                        ProtocolMessage = new OpenIdConnectMessage
                        {
                            IdToken = Guid.NewGuid().ToString(),
                            AccessToken = token
                        }
                    },
                    validator,
                    new ExpectedException(typeof(ArgumentNullException))
                );
                dataset.Add(
                    new JwtSecurityToken(
                        claims: new List<Claim> { new Claim("at_hash", hashClaimValue256) },
                        signingCredentials: IdentityUtilities.DefaultAsymmetricSigningCredentials
                        ),
                    new OpenIdConnectProtocolValidationContext()
                    {
                        ProtocolMessage = new OpenIdConnectMessage
                        {
                            AccessToken = token,
                        }
                    },
                    validator,
                    ExpectedException.NoExceptionExpected
                );
                dataset.Add(
                    new JwtSecurityToken
                        (
                            claims: new List<Claim> { new Claim("at_hash", hashClaimValue512) },
                            signingCredentials: IdentityUtilities.DefaultAsymmetricSigningCredentials
                        ),
                    new OpenIdConnectProtocolValidationContext()
                    {
                        ProtocolMessage = new OpenIdConnectMessage
                        {
                            AccessToken = token,
                        }
                    },
                    validator,
                    new ExpectedException(typeof(OpenIdConnectProtocolInvalidAtHashException), "IDX10348:", typeof(OpenIdConnectProtocolException))
                );
                dataset.Add(
                    new JwtSecurityToken
                        (
                            claims: new List<Claim> { new Claim("at_hash", hashClaimValue256) },
                            signingCredentials: IdentityUtilities.DefaultAsymmetricSigningCredentials
                        ),
                    new OpenIdConnectProtocolValidationContext()
                    {
                        ProtocolMessage = new OpenIdConnectMessage
                        {
                            AccessToken = Guid.NewGuid().ToString(),
                        }
                    },
                    validator,
                    new ExpectedException(typeof(OpenIdConnectProtocolInvalidAtHashException), "IDX10348:", typeof(OpenIdConnectProtocolException))
                );
                dataset.Add(
                    new JwtSecurityToken
                        (
                            claims: new List<Claim> { new Claim("at_hash", hashClaimValue256), new Claim("at_hash", hashClaimValue256) },
                            signingCredentials: IdentityUtilities.DefaultAsymmetricSigningCredentials
                        ),
                    new OpenIdConnectProtocolValidationContext()
                    {
                        ProtocolMessage = new OpenIdConnectMessage
                        {
                            AccessToken = Guid.NewGuid().ToString(),
                        }
                    },
                    validator,
                    new ExpectedException(typeof(OpenIdConnectProtocolInvalidAtHashException), "IDX10311:")
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
                var validatorRequireStateValidationFalse = new PublicOpenIdConnectProtocolValidator { RequireStateValidation = false };
                var state1 = Guid.NewGuid().ToString();
                var state2 = Guid.NewGuid().ToString();

                // validationContext is null
                dataset.Add(null, validator, ExpectedException.ArgumentNullException());
                // validationContext does not contain state and RequireState is true
                dataset.Add(
                    new OpenIdConnectProtocolValidationContext
                    {
                        ProtocolMessage = new OpenIdConnectMessage()
                    },
                    validator,
                    new ExpectedException(typeof(OpenIdConnectProtocolInvalidStateException), "IDX10329:")
                );
                // validationContext does not contain state and RequireState is false
                dataset.Add(
                    new OpenIdConnectProtocolValidationContext
                    {
                        ProtocolMessage = new OpenIdConnectMessage()
                    },
                    validatorRequireStateFalse,
                    ExpectedException.NoExceptionExpected
                );
                // validationContext contains state but the message does not have state
                dataset.Add(
                    new OpenIdConnectProtocolValidationContext
                    {
                        ProtocolMessage = new OpenIdConnectMessage(),
                        State = state1
                    },
                    validator,
                    new ExpectedException(typeof(OpenIdConnectProtocolInvalidStateException), "IDX10330:")
                );
                // state match
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
                // state mismatch
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
                    new ExpectedException(typeof(OpenIdConnectProtocolInvalidStateException), "IDX10331:")
                );

                // state mismatch but RequireStateValidation is false
                dataset.Add(
                    new OpenIdConnectProtocolValidationContext()
                    {
                        State = state1,
                        ProtocolMessage = new OpenIdConnectMessage
                        {
                            State = state2
                        }
                    },
                    validatorRequireStateValidationFalse,
                    ExpectedException.NoExceptionExpected
                );
                return dataset;
            }
        }
#pragma warning disable CS3016 // Arrays as attribute arguments is not CLS-compliant
        [Theory]
        [InlineData(SecurityAlgorithms.EcdsaSha256, "SHA256", true)]
        [InlineData(SecurityAlgorithms.EcdsaSha256Signature, "SHA256", true)]
        [InlineData(SecurityAlgorithms.HmacSha256, "SHA256", true)]
        [InlineData(SecurityAlgorithms.RsaSha256, "SHA256", true)]
        [InlineData(SecurityAlgorithms.RsaSha256Signature, "SHA256", true)]
        [InlineData(SecurityAlgorithms.RsaSsaPssSha256, "SHA256", true)]
        [InlineData(SecurityAlgorithms.EcdsaSha384, "SHA384", true)]
        [InlineData(SecurityAlgorithms.EcdsaSha384Signature, "SHA384", true)]
        [InlineData(SecurityAlgorithms.HmacSha384, "SHA384", true)]
        [InlineData(SecurityAlgorithms.RsaSha384, "SHA384", true)]
        [InlineData(SecurityAlgorithms.RsaSha384Signature, "SHA384", true)]
        [InlineData(SecurityAlgorithms.RsaSsaPssSha384, "SHA384", true)]
        [InlineData(SecurityAlgorithms.EcdsaSha512, "SHA512", true)]
        [InlineData(SecurityAlgorithms.EcdsaSha512Signature, "SHA512", true)]
        [InlineData(SecurityAlgorithms.HmacSha512, "SHA512", true)]
        [InlineData(SecurityAlgorithms.RsaSha512, "SHA512", true)]
        [InlineData(SecurityAlgorithms.RsaSha512Signature, "SHA512", true)]
        [InlineData(SecurityAlgorithms.RsaSsaPssSha512, "SHA512", true)]
        [InlineData(SecurityAlgorithms.ExclusiveC14nWithComments, "SHA512", false)]
        [InlineData(SecurityAlgorithms.Aes128KeyWrap, "SHA512", false)]
#pragma warning restore CS3016 // Arrays as attribute arguments is not CLS-compliant
        public void DefaultAlgorithmMapTest(string algorithm, string expectedHash, bool shouldFind)
        {
            var protocolValidator = new OpenIdConnectProtocolValidator();
            string hashFound;
            Assert.True(protocolValidator.HashAlgorithmMap.TryGetValue(algorithm, out hashFound) == shouldFind);
            if (shouldFind)
                Assert.True(hashFound.Equals(expectedHash, StringComparison.Ordinal));
        }

#pragma warning disable CS3016 // Arrays as attribute arguments is not CLS-compliant
        [Theory, MemberData("HashAlgExtensibilityDataSet")]
#pragma warning restore CS3016 // Arrays as attribute arguments is not CLS-compliant
        public void HashAlgorithmExtensibility(OpenIdConnectProtocolValidator protocolValidator, string alg, Type algorithmType, ExpectedException ee)
        {
            ee.Verbose = false;
            try
            {
                var hash = protocolValidator.GetHashAlgorithm(alg);
                ee.ProcessNoException();
                Assert.True(hash.GetType() == algorithmType, string.Format(CultureInfo.InvariantCulture, "hash.GetType() != algorithmType: '{0}' : '{1}'", hash.GetType(), algorithmType));
            }
            catch (Exception ex)
            {
                ee.ProcessException(ex);
            }
        }

        public static TheoryData<OpenIdConnectProtocolValidator, string, Type, ExpectedException> HashAlgExtensibilityDataSet
        {
            get
            {
                var dataSet = new TheoryData<OpenIdConnectProtocolValidator, string, Type, ExpectedException>();

                // CustomCryptoProviderFactory understands this 'hash' algorithm
                var customHashAlgorithm = new CustomHashAlgorithm();
                var customCryptoProviderFactory = new CustomCryptoProviderFactory()
                {
                    HashAlgorithm = customHashAlgorithm
                };

                var validator = new OpenIdConnectProtocolValidator()
                {
                    CryptoProviderFactory = customCryptoProviderFactory
                };

                dataSet.Add(validator, SecurityAlgorithms.ExclusiveC14nWithComments, customHashAlgorithm.GetType(), ExpectedException.NoExceptionExpected);

                // Default CryptoProviderFactory faults on this 'hash' algorithm
                validator = new OpenIdConnectProtocolValidator()
                {
                    CryptoProviderFactory = new CryptoProviderFactory()
                };

                dataSet.Add(validator, SecurityAlgorithms.ExclusiveC14nWithComments, customHashAlgorithm.GetType(), new ExpectedException(typeof(OpenIdConnectProtocolException), "IDX10301:", typeof(InvalidOperationException)));

                // Adjust mapping table, and Default CryptoProviderFactory will find 'hash' algorithm
                var sha2 = SHA256.Create();
                validator = new OpenIdConnectProtocolValidator();
                validator.HashAlgorithmMap[SecurityAlgorithms.ExclusiveC14nWithComments] = SecurityAlgorithms.Sha256;
                dataSet.Add(validator, SecurityAlgorithms.ExclusiveC14nWithComments, sha2.GetType(), ExpectedException.NoExceptionExpected);

                // Support a single hash algorithm, add CryptoProvider that supports hash algorithm
                var cryptoProvider = new CustomCryptoProvider()
                {
                    HashAlgorithm = customHashAlgorithm,
                    IsSupportedResult = true
                };

                cryptoProvider.AdditionalHashAlgorithms.Add(SecurityAlgorithms.ExclusiveC14nWithComments);

                validator = new OpenIdConnectProtocolValidator()
                {
                    CryptoProviderFactory = new CryptoProviderFactory()
                };

                validator.CryptoProviderFactory.CustomCryptoProvider = cryptoProvider;
                dataSet.Add(validator, SecurityAlgorithms.ExclusiveC14nWithComments, customHashAlgorithm.GetType(), ExpectedException.NoExceptionExpected);

                return dataSet;
            }
        }

#pragma warning disable CS3016 // Arrays as attribute arguments is not CLS-compliant
        [Theory, MemberData("GetHashAlgDataSet")]
#pragma warning restore CS3016 // Arrays as attribute arguments is not CLS-compliant
        public void GetHashAlgorithm(OpenIdConnectProtocolValidator protocolValidator, string alg, Type algorithmType, ExpectedException ee)
        {
            ee.Verbose = false;
            try
            {
                var hash = protocolValidator.GetHashAlgorithm(alg);
                ee.ProcessNoException();
                Assert.True(hash.GetType() == algorithmType);
            }
            catch(Exception ex)
            {
                ee.ProcessException(ex);
            }
        }

        public static TheoryData<OpenIdConnectProtocolValidator, string, Type, ExpectedException> GetHashAlgDataSet
        {
            get
            {
                var validator = new OpenIdConnectProtocolValidator();
                var sha2 = SHA256.Create();
                var sha3 = SHA384.Create();
                var sha5 = SHA512.Create();

                return new TheoryData<OpenIdConnectProtocolValidator, string, Type, ExpectedException>
                {
                    {validator, SecurityAlgorithms.EcdsaSha256, sha2.GetType(), ExpectedException.NoExceptionExpected },
                    {validator, SecurityAlgorithms.EcdsaSha256Signature, sha2.GetType(), ExpectedException.NoExceptionExpected},
                    {validator, SecurityAlgorithms.HmacSha256, sha2.GetType(), ExpectedException.NoExceptionExpected},
                    {validator, SecurityAlgorithms.RsaSha256, sha2.GetType(), ExpectedException.NoExceptionExpected},
                    {validator, SecurityAlgorithms.RsaSha256Signature, sha2.GetType(), ExpectedException.NoExceptionExpected},
                    {validator, SecurityAlgorithms.RsaSsaPssSha256, sha2.GetType(), ExpectedException.NoExceptionExpected},

                    {validator, SecurityAlgorithms.EcdsaSha384, sha3.GetType(), ExpectedException.NoExceptionExpected },
                    {validator, SecurityAlgorithms.HmacSha384, sha3.GetType(), ExpectedException.NoExceptionExpected },
                    {validator, SecurityAlgorithms.RsaSha384, sha3.GetType(), ExpectedException.NoExceptionExpected},
                    {validator, SecurityAlgorithms.RsaSsaPssSha384, sha3.GetType(), ExpectedException.NoExceptionExpected},
                    {validator, SecurityAlgorithms.RsaSha384Signature, sha3.GetType(), ExpectedException.NoExceptionExpected},
                    {validator, SecurityAlgorithms.EcdsaSha384Signature, sha3.GetType(), ExpectedException.NoExceptionExpected},

                    {validator, SecurityAlgorithms.RsaSha512Signature, sha5.GetType(), ExpectedException.NoExceptionExpected },
                    {validator, SecurityAlgorithms.RsaSsaPssSha512, sha5.GetType(), ExpectedException.NoExceptionExpected },
                    {validator, SecurityAlgorithms.EcdsaSha512, sha5.GetType(), ExpectedException.NoExceptionExpected},
                    {validator, SecurityAlgorithms.EcdsaSha512Signature, sha5.GetType(), ExpectedException.NoExceptionExpected},
                    {validator, SecurityAlgorithms.HmacSha512, sha5.GetType(), ExpectedException.NoExceptionExpected},
                    {validator, SecurityAlgorithms.RsaSha512, sha5.GetType(), ExpectedException.NoExceptionExpected},

                    {validator, SecurityAlgorithms.ExclusiveC14nWithComments, sha5.GetType(), new ExpectedException(typeof(OpenIdConnectProtocolException), "IDX10301:", typeof(InvalidOperationException))}
                };
            }
        }
    }

    public class PublicOpenIdConnectProtocolValidator : OpenIdConnectProtocolValidator
    {
        public void PublicValidateIdToken(JwtSecurityToken token, OpenIdConnectProtocolValidationContext context)
        {
            if (context != null)
                context.ValidatedIdToken = token;
            base.ValidateIdToken(context);
        }

        public void PublicValidateCHash(JwtSecurityToken token, OpenIdConnectProtocolValidationContext context)
        {
            if (context != null)
                context.ValidatedIdToken = token;
            base.ValidateCHash(context);
        }

        public void PublicValidateAtHash(JwtSecurityToken token, OpenIdConnectProtocolValidationContext context)
        {
            if (context != null)
                context.ValidatedIdToken = token;
            base.ValidateAtHash(context);
        }

        public void PublicValidateNonce(JwtSecurityToken token, OpenIdConnectProtocolValidationContext context)
        {
            if (context != null)
                context.ValidatedIdToken = token;
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

    class SampleListener : EventListener
    {
        public string TraceBuffer { get; set; }

        protected override void OnEventWritten(EventWrittenEventArgs eventData)
        {
            if (eventData != null && eventData.Payload.Count > 0)
            {
                TraceBuffer += eventData.Payload[0] + "\n";
            }
        }
    }
}
