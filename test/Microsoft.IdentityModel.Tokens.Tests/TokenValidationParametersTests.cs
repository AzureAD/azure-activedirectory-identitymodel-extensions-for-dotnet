// Copyright (c) Microsoft Corporation. All rights reserved.
// Licensed under the MIT License.

using System;
using System.Collections.Generic;
using System.Reflection;
using System.Security.Claims;
using Microsoft.IdentityModel.Protocols;
using Microsoft.IdentityModel.Protocols.OpenIdConnect;
using Microsoft.IdentityModel.Protocols.WsFederation;
using Microsoft.IdentityModel.TestUtils;
using Xunit;
using Xunit.Sdk;

namespace Microsoft.IdentityModel.Tokens.Tests
{
    public class TokenValidationParametersTests
    {
        int ExpectedPropertyCount = 58;

        [Fact]
        public void Publics()
        {
            TokenValidationParameters validationParameters = new TokenValidationParameters();
            Type type = typeof(TokenValidationParameters);
            PropertyInfo[] properties = type.GetProperties();
            if (properties.Length != ExpectedPropertyCount)
                Assert.True(false, $"Number of properties has changed from {ExpectedPropertyCount} to: " + properties.Length + ", adjust tests");

            TokenValidationParameters actorValidationParameters = new TokenValidationParameters();
            SecurityKey issuerSigningKey = KeyingMaterial.DefaultX509Key_2048_Public;
            SecurityKey issuerSigningKey2 = KeyingMaterial.RsaSecurityKey_2048;

            List<SecurityKey> issuerSigningKeys =
                new List<SecurityKey>
                {
                    KeyingMaterial.DefaultX509Key_2048_Public,
                    KeyingMaterial.RsaSecurityKey_2048
                };

            List<SecurityKey> issuerSigningKeysDup =
                new List<SecurityKey>
                {
                    KeyingMaterial.DefaultX509Key_2048_Public,
                    KeyingMaterial.RsaSecurityKey_2048
                };

            string validAudience = "ValidAudience";
            List<string> validAudiences = new List<string> { validAudience };
            string validIssuer = "ValidIssuer";
            List<string> validIssuers = new List<string> { validIssuer };

            var propertyBag =
                new Dictionary<string, Object>
                {
                    { "CustomKey", "CustomValue" }
                };

            TypeValidator typeValidator = (typ, token, parameters) => "ActualType";

            AlgorithmValidator algorithmValidator = ValidationDelegates.AlgorithmValidatorBuilder(false);

            var validTypes = new List<string> { "ValidType1", "ValidType2", "ValidType3" };

            var validAlgorithms = new List<string> { "RSA2048", "RSA1024" };

            TokenValidationParameters validationParametersInline = new TokenValidationParameters()
            {
                AlgorithmValidator = algorithmValidator,
                ActorValidationParameters = actorValidationParameters,
                AudienceValidator = ValidationDelegates.AudienceValidatorReturnsTrue,
                IssuerSigningKey = issuerSigningKey,
                IssuerSigningKeyResolver = (token, securityToken, keyIdentifier, tvp) => { return new List<SecurityKey> { issuerSigningKey }; },
                IssuerSigningKeys = issuerSigningKeys,
                IssuerValidator = ValidationDelegates.IssuerValidatorEcho,
                LifetimeValidator = ValidationDelegates.LifetimeValidatorReturnsTrue,
                LogTokenId = true,
                LogValidationExceptions = true,
                PropertyBag = propertyBag,
                SignatureValidator = ValidationDelegates.SignatureValidatorReturnsJwtTokenAsIs,
                SaveSigninToken = true,
                TypeValidator = typeValidator,
                ValidAlgorithms = validAlgorithms,
                ValidateAudience = false,
                ValidateIssuer = false,
                ValidAudience = validAudience,
                ValidAudiences = validAudiences,
                ValidIssuer = validIssuer,
                ValidIssuers = validIssuers,
                ValidTypes = validTypes
            };

            Assert.True(object.ReferenceEquals(actorValidationParameters, validationParametersInline.ActorValidationParameters));
            Assert.True(object.ReferenceEquals(validationParametersInline.IssuerSigningKey, issuerSigningKey));
            Assert.True(object.ReferenceEquals(validationParametersInline.PropertyBag, propertyBag));
            Assert.True(validationParametersInline.SaveSigninToken);
            Assert.False(validationParametersInline.ValidateAudience);
            Assert.False(validationParametersInline.ValidateIssuer);
            Assert.True(object.ReferenceEquals(validationParametersInline.ValidAlgorithms, validAlgorithms));
            Assert.True(object.ReferenceEquals(validationParametersInline.AlgorithmValidator, algorithmValidator));
            Assert.True(object.ReferenceEquals(validationParametersInline.TypeValidator, typeValidator));
            Assert.True(object.ReferenceEquals(validationParametersInline.ValidAudience, validAudience));
            Assert.True(object.ReferenceEquals(validationParametersInline.ValidAudiences, validAudiences));
            Assert.True(object.ReferenceEquals(validationParametersInline.ValidIssuer, validIssuer));
            Assert.True(validationParametersInline.IgnoreTrailingSlashWhenValidatingAudience);

            TokenValidationParameters validationParametersSets = new TokenValidationParameters();
            validationParametersSets.AlgorithmValidator = algorithmValidator;
            validationParametersSets.ActorValidationParameters = actorValidationParameters;
            validationParametersSets.AudienceValidator = ValidationDelegates.AudienceValidatorReturnsTrue;
            validationParametersSets.IssuerSigningKey = KeyingMaterial.DefaultX509Key_2048_Public;
            validationParametersSets.IssuerSigningKeyResolver = (token, securityToken, keyIdentifier, tvp) => { return new List<SecurityKey> { issuerSigningKey2 }; };
            validationParametersSets.IssuerSigningKeys = issuerSigningKeysDup;
            validationParametersSets.IssuerValidator = ValidationDelegates.IssuerValidatorEcho;
            validationParametersSets.LifetimeValidator = ValidationDelegates.LifetimeValidatorReturnsTrue;
            validationParametersSets.LogTokenId = true;
            validationParametersSets.LogValidationExceptions = true;
            validationParametersSets.PropertyBag = propertyBag;
            validationParametersSets.SignatureValidator = ValidationDelegates.SignatureValidatorReturnsJwtTokenAsIs;
            validationParametersSets.SaveSigninToken = true;
            validationParametersSets.TypeValidator = typeValidator;
            validationParametersSets.ValidateAudience = false;
            validationParametersSets.ValidateIssuer = false;
            validationParametersSets.ValidAlgorithms = validAlgorithms;
            validationParametersSets.ValidAudience = validAudience;
            validationParametersSets.ValidAudiences = validAudiences;
            validationParametersSets.ValidIssuer = validIssuer;
            validationParametersSets.ValidIssuers = validIssuers;
            validationParametersSets.ValidTypes = validTypes;

            var compareContext = new CompareContext();
            IdentityComparer.AreEqual(validationParametersInline, validationParametersSets, compareContext);

            // only exlude 'IsClone' when comparing Clone vs. Original.
            var instanceContext = new CompareContext();
            instanceContext.PropertiesToIgnoreWhenComparing.Add(typeof(TokenValidationParameters), new List<string> { "IsClone" });
            TokenValidationParameters validationParametersInLineClone = validationParametersInline.Clone();
            IdentityComparer.AreEqual(validationParametersInLineClone, validationParametersInline, instanceContext);
            if (!validationParametersInLineClone.IsClone)
                instanceContext.AddDiff("!validationParametersInLineClone.IsClone)");

            string id = Guid.NewGuid().ToString();
            DerivedTokenValidationParameters derivedValidationParameters = new DerivedTokenValidationParameters(id, validationParametersInline);
            DerivedTokenValidationParameters derivedValidationParametersCloned = derivedValidationParameters.Clone() as DerivedTokenValidationParameters;
            IdentityComparer.AreEqual(derivedValidationParameters, derivedValidationParametersCloned, instanceContext);
            IdentityComparer.AreEqual(derivedValidationParameters.InternalString, derivedValidationParametersCloned.InternalString, compareContext);
            if (!derivedValidationParametersCloned.IsClone)
                instanceContext.AddDiff("!derivedValidationParametersCloned.IsClone)");

            TokenValidationParameters tokenValidationParametersClone = validationParametersInline.Clone();
            IdentityComparer.AreEqual(tokenValidationParametersClone, tokenValidationParametersClone, instanceContext);

            compareContext.Merge(instanceContext);

            TestUtilities.AssertFailIfErrors(compareContext);
        }

        [Fact]
        public void GetSets()
        {
            TokenValidationParameters validationParameters = new TokenValidationParameters();
            Type type = typeof(TokenValidationParameters);
            PropertyInfo[] properties = type.GetProperties();
            if (properties.Length != ExpectedPropertyCount)
                Assert.True(false, $"Number of public fields has changed from {ExpectedPropertyCount} to: " + properties.Length + ", adjust tests");

            GetSetContext context =
                new GetSetContext
                {
                    PropertyNamesAndSetGetValue = new List<KeyValuePair<string, List<object>>>
                    {
                        new KeyValuePair<string, List<object>>("ActorValidationParameters", new List<object>{(TokenValidationParameters)null, new TokenValidationParameters(), new TokenValidationParameters()}),
                        new KeyValuePair<string, List<object>>("AuthenticationType", new List<object>{(string)null, Guid.NewGuid().ToString(), Guid.NewGuid().ToString()}),
                        new KeyValuePair<string, List<object>>("ClockSkew", new List<object>{TokenValidationParameters.DefaultClockSkew, TimeSpan.FromHours(2), TimeSpan.FromMinutes(1)}),
                        new KeyValuePair<string, List<object>>("IgnoreTrailingSlashWhenValidatingAudience",  new List<object>{true, false, true}),
                        new KeyValuePair<string, List<object>>("IssuerSigningKey", new List<object>{(SecurityKey)null, KeyingMaterial.DefaultX509Key_2048, KeyingMaterial.RsaSecurityKey_2048}),
                        new KeyValuePair<string, List<object>>("IssuerSigningKeys", new List<object>{(IEnumerable<SecurityKey>)null, new List<SecurityKey>{KeyingMaterial.DefaultX509Key_2048, KeyingMaterial.RsaSecurityKey_1024}, new List<SecurityKey>()}),
                        new KeyValuePair<string, List<object>>("NameClaimType", new List<object>{ClaimsIdentity.DefaultNameClaimType, Guid.NewGuid().ToString(), Guid.NewGuid().ToString()}),
                        new KeyValuePair<string, List<object>>("PropertyBag", new List<object>{(IDictionary<string, Object>)null, new Dictionary<string, Object> {{"CustomKey", "CustomValue"}}, new Dictionary<string, Object>()}),
                        new KeyValuePair<string, List<object>>("RoleClaimType", new List<object>{ClaimsIdentity.DefaultRoleClaimType, Guid.NewGuid().ToString(), Guid.NewGuid().ToString()}),
                        new KeyValuePair<string, List<object>>("RequireExpirationTime", new List<object>{true, false, true}),
                        new KeyValuePair<string, List<object>>("RequireSignedTokens", new List<object>{true, false, true}),
                        new KeyValuePair<string, List<object>>("SaveSigninToken", new List<object>{false, true, false}),
                        new KeyValuePair<string, List<object>>("ValidateActor", new List<object>{false, true, false}),
                        new KeyValuePair<string, List<object>>("ValidateAudience", new List<object>{true, false, true}),
                        new KeyValuePair<string, List<object>>("ValidateIssuer", new List<object>{true, false, true}),
                        new KeyValuePair<string, List<object>>("ValidateLifetime", new List<object>{true, false, true}),
                        new KeyValuePair<string, List<object>>("ValidateTokenReplay", new List<object>{false, true, false}),
                        new KeyValuePair<string, List<object>>("ValidIssuer", new List<object>{(string)null, Guid.NewGuid().ToString(), Guid.NewGuid().ToString()}),
                        new KeyValuePair<string, List<object>>("ConfigurationManager", new List<object>{(BaseConfigurationManager)null, new ConfigurationManager<OpenIdConnectConfiguration>("http://someaddress.com", new OpenIdConnectConfigurationRetriever()), new ConfigurationManager<WsFederationConfiguration>("http://someaddress.com", new WsFederationConfigurationRetriever()) }),
                    },
                    Object = validationParameters,
                };

            TestUtilities.GetSet(context);
            TestUtilities.AssertFailIfErrors("TokenValidationParametersTests: GetSets", context.Errors);
            Assert.Null(validationParameters.AudienceValidator);
            Assert.Null(validationParameters.LifetimeValidator);
            Assert.Null(validationParameters.IssuerSigningKeyResolver);
            Assert.Null(validationParameters.IssuerValidator);
            Assert.Null(validationParameters.TypeValidator);
            Assert.Null(validationParameters.ValidAudiences);
            Assert.Null(validationParameters.ValidIssuers);
            Assert.Null(validationParameters.SignatureValidator);
        }

        [Fact]
        public void Clone()
        {
            object obj = new object();
            var compareContext = new CompareContext();

            TokenValidationParameters validationParameters = new TokenValidationParameters();
            validationParameters.PropertyBag = new Dictionary<string, object> { { "object", obj } };
            validationParameters.InstancePropertyBag["object"] = obj;

            compareContext.PropertiesToIgnoreWhenComparing.Add(typeof(TokenValidationParameters), new List<string> { "InstancePropertyBag", "IsClone" });
            TokenValidationParameters validationParametersClone = validationParameters.Clone();
            IdentityComparer.AreEqual(validationParametersClone, validationParameters, compareContext);
            if (validationParameters.IsClone)
                compareContext.AddDiff("if (validationParameters.IsClone), IsCone should be false");

            if (!validationParametersClone.IsClone)
                compareContext.AddDiff("if (!validationParametersClone.IsClone), IsCone should be true");

            if (validationParametersClone.InstancePropertyBag.Count != 0)
                compareContext.AddDiff("validationParametersClone.InstancePropertyBag.Count != 0), should be empty.");

            TestUtilities.AssertFailIfErrors(compareContext);
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
                DerivedTokenValidationParameters derivedTokenValidationParameters = new DerivedTokenValidationParameters(this);
                derivedTokenValidationParameters.IsClone = true;
                return derivedTokenValidationParameters;
            }
        }
    }
}
