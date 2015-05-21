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

using System.Collections.Generic;
using System.IdentityModel.Tokens;
using System.Reflection;
using System.Security.Claims;
using System.Text;
using Xunit;

namespace System.IdentityModel.Test
{
    public class TokenValidationParametersTests
    {
        [Fact( DisplayName = "TokenValidationParametersTests: Publics")]
        public void Publics()
        {
            TokenValidationParameters validationParameters = new TokenValidationParameters();
            Type type = typeof(TokenValidationParameters);
            PropertyInfo[] properties = type.GetProperties();
            if (properties.Length != 27)
                Assert.True(false, "Number of properties has changed from 27 to: " + properties.Length + ", adjust tests");

            SecurityKey issuerSigningKey = KeyingMaterial.DefaultX509Key_Public_2048;
            SecurityKey issuerSigningKey2 = KeyingMaterial.RsaSecurityKey_2048;

            List<SecurityKey> issuerSigningKeys =
                new List<SecurityKey>
                {
                    KeyingMaterial.DefaultX509Key_Public_2048,
                    KeyingMaterial.RsaSecurityKey_2048
                };

            List<SecurityKey> issuerSigningKeysDup =
                new List<SecurityKey>
                {
                    KeyingMaterial.DefaultX509Key_Public_2048,
                    KeyingMaterial.RsaSecurityKey_2048
                };

            string validAudience = "ValidAudience";
            List<string> validAudiences = new List<string> { validAudience };
            string validIssuer = "ValidIssuer";
            List<string> validIssuers = new List<string> { validIssuer };

            TokenValidationParameters validationParametersInline = new TokenValidationParameters()
            {
                AudienceValidator = IdentityUtilities.AudienceValidatorReturnsTrue,
                IssuerSigningKey = issuerSigningKey,
                IssuerSigningKeyResolver = (token, securityToken, keyIdentifier, tvp) => { return issuerSigningKey; },
                IssuerSigningKeys = issuerSigningKeys,
                IssuerValidator = IdentityUtilities.IssuerValidatorEcho,
                LifetimeValidator = IdentityUtilities.LifetimeValidatorReturnsTrue,
                SaveSigninToken = true,
                ValidateAudience = false,
                ValidateIssuer = false,
                ValidAudience = validAudience,
                ValidAudiences = validAudiences,
                ValidIssuer = validIssuer,
                ValidIssuers = validIssuers,
            };

            Assert.True(object.ReferenceEquals(validationParametersInline.IssuerSigningKey, issuerSigningKey));
            Assert.True(validationParametersInline.SaveSigninToken);
            Assert.False(validationParametersInline.ValidateAudience);
            Assert.False(validationParametersInline.ValidateIssuer);
            Assert.True(object.ReferenceEquals(validationParametersInline.ValidAudience, validAudience));
            Assert.True(object.ReferenceEquals(validationParametersInline.ValidAudiences, validAudiences));
            Assert.True(object.ReferenceEquals(validationParametersInline.ValidIssuer, validIssuer));

            TokenValidationParameters validationParametersSets = new TokenValidationParameters();
            validationParametersSets.AudienceValidator = IdentityUtilities.AudienceValidatorReturnsTrue;
            validationParametersSets.IssuerSigningKey = KeyingMaterial.DefaultX509Key_Public_2048;
            validationParametersSets.IssuerSigningKeyResolver = (token, securityToken, keyIdentifier, tvp) => { return issuerSigningKey2; };
            validationParametersSets.IssuerSigningKeys = issuerSigningKeysDup;
            validationParametersSets.IssuerValidator = IdentityUtilities.IssuerValidatorEcho;
            validationParametersSets.LifetimeValidator = IdentityUtilities.LifetimeValidatorReturnsTrue;
            validationParametersSets.SaveSigninToken = true;
            validationParametersSets.ValidateAudience = false;
            validationParametersSets.ValidateIssuer = false;
            validationParametersSets.ValidAudience = validAudience;
            validationParametersSets.ValidAudiences = validAudiences;
            validationParametersSets.ValidIssuer = validIssuer;
            validationParametersSets.ValidIssuers = validIssuers;

            Assert.True(IdentityComparer.AreEqual<TokenValidationParameters>(validationParametersInline, validationParametersSets));

            TokenValidationParameters tokenValidationParametersCloned = validationParametersInline.Clone() as TokenValidationParameters;
            Assert.True(IdentityComparer.AreEqual<TokenValidationParameters>(tokenValidationParametersCloned, validationParametersInline));
            //tokenValidationParametersCloned.AudienceValidator(new string[]{"bob"}, JwtTestTokens.Simple();

            string id = Guid.NewGuid().ToString();
            DerivedTokenValidationParameters derivedValidationParameters = new DerivedTokenValidationParameters(id, validationParametersInline);
            DerivedTokenValidationParameters derivedValidationParametersCloned = derivedValidationParameters.Clone() as DerivedTokenValidationParameters;
            Assert.True(IdentityComparer.AreEqual<TokenValidationParameters>(derivedValidationParameters, derivedValidationParametersCloned));
            Assert.Equal(derivedValidationParameters.InternalString, derivedValidationParametersCloned.InternalString);
        }

        [Fact( DisplayName = "TokenValidationParametersTests: GetSets, covers defaults")]
        public void GetSets()
        {
            TokenValidationParameters validationParameters = new TokenValidationParameters();
            Type type = typeof(TokenValidationParameters);
            PropertyInfo[] properties = type.GetProperties();
            if (properties.Length != 27)
                Assert.True(false, "Number of public fields has changed from 27 to: " + properties.Length + ", adjust tests");

            GetSetContext context =
                new GetSetContext
                {
                    PropertyNamesAndSetGetValue = new List<KeyValuePair<string, List<object>>>
                    {
                        new KeyValuePair<string, List<object>>("AuthenticationType", new List<object>{(string)null, Guid.NewGuid().ToString(), Guid.NewGuid().ToString()}),
                        //new KeyValuePair<string, List<object>>("CertificateValidator", new List<object>{(string)null, X509CertificateValidator.None, X509CertificateValidatorEx.None}),
                        new KeyValuePair<string, List<object>>("ClockSkew", new List<object>{TokenValidationParameters.DefaultClockSkew, TimeSpan.FromHours(2), TimeSpan.FromMinutes(1)}),
                        new KeyValuePair<string, List<object>>("IssuerSigningKey", new List<object>{(SecurityKey)null, KeyingMaterial.DefaultX509Key_2048, KeyingMaterial.RsaSecurityKey_2048}),
                        new KeyValuePair<string, List<object>>("IssuerSigningKeys", new List<object>{(IEnumerable<SecurityKey>)null, new List<SecurityKey>{KeyingMaterial.DefaultX509Key_2048, KeyingMaterial.RsaSecurityKey_1024}, new List<SecurityKey>()}),
                        new KeyValuePair<string, List<object>>("NameClaimType", new List<object>{ClaimsIdentity.DefaultNameClaimType, Guid.NewGuid().ToString(), Guid.NewGuid().ToString()}),
                        new KeyValuePair<string, List<object>>("RoleClaimType", new List<object>{ClaimsIdentity.DefaultRoleClaimType, Guid.NewGuid().ToString(), Guid.NewGuid().ToString()}),
                        new KeyValuePair<string, List<object>>("RequireExpirationTime", new List<object>{true, false, true}),
                        new KeyValuePair<string, List<object>>("RequireSignedTokens", new List<object>{true, false, true}),
                        new KeyValuePair<string, List<object>>("SaveSigninToken", new List<object>{false, true, false}),
                        new KeyValuePair<string, List<object>>("ValidateActor", new List<object>{false, true, false}),
                        new KeyValuePair<string, List<object>>("ValidateAudience", new List<object>{true, false, true}),
                        new KeyValuePair<string, List<object>>("ValidateIssuer", new List<object>{true, false, true}),
                        new KeyValuePair<string, List<object>>("ValidateLifetime", new List<object>{true, false, true}),
                        new KeyValuePair<string, List<object>>("ValidIssuer", new List<object>{(string)null, Guid.NewGuid().ToString(), Guid.NewGuid().ToString()}),
                    },
                    Object = validationParameters,
                };
            TestUtilities.GetSet(context);
            TestUtilities.AssertFailIfErrors("TokenValidationParametersTests: GetSets", context.Errors);

            Assert.Null(validationParameters.AudienceValidator);
            Assert.NotNull(validationParameters.ClientDecryptionTokens);
            Assert.Equal(validationParameters.ClientDecryptionTokens.Count, 0);
            Assert.Null(validationParameters.LifetimeValidator);
            Assert.Null(validationParameters.IssuerSigningKeyResolver);
            Assert.Null(validationParameters.IssuerValidator);
            Assert.Null(validationParameters.ValidAudiences);
            Assert.Null(validationParameters.ValidIssuers);

        }

        class DerivedTokenValidationParameters : TokenValidationParameters
        {
            string _internalString;
            public DerivedTokenValidationParameters(string internalString, TokenValidationParameters validationParameters)
                : base(validationParameters)
            {
                _internalString = internalString;
            }

            protected DerivedTokenValidationParameters(DerivedTokenValidationParameters other)
                : base(other)
            {
                _internalString = other._internalString;
            }

            public string InternalString { get { return _internalString; } }

            public override TokenValidationParameters Clone()
            {
                return new DerivedTokenValidationParameters(this);
            }
        }
    }
}
