// Copyright (c) Microsoft Corporation. All rights reserved.
// Licensed under the MIT License.

using System;
using System.Security.Claims;
using Microsoft.IdentityModel.JsonWebTokens;
using Microsoft.IdentityModel.TestUtils;
using Xunit;

namespace Microsoft.IdentityModel.Tokens.Tests
{
    [Collection(nameof(ClaimsIdentityFactoryTests))]
    public class ClaimsIdentityFactoryTests
    {
        [Theory]
        [InlineData(true)]
        [InlineData(false)]
        public void Create_FromTokenValidationParameters_ReturnsCorrectClaimsIdentity(bool useClaimsIdentity)
        {
            AppContext.SetSwitch(AppContextSwitches.UseClaimsIdentityTypeSwitch, useClaimsIdentity);

            var jsonWebToken = new JsonWebToken(Default.Jwt(Default.SecurityTokenDescriptor()));
            var tokenValidationParameters = new TokenValidationParameters();
            tokenValidationParameters.AuthenticationType = "custom-authentication-type";
            tokenValidationParameters.NameClaimType = "custom-name";
            tokenValidationParameters.RoleClaimType = "custom-role";

            var actualClaimsIdentity = ClaimsIdentityFactory.Create(jsonWebToken, tokenValidationParameters, Default.Issuer);

            Assert.Equal(tokenValidationParameters.AuthenticationType, actualClaimsIdentity.AuthenticationType);
            Assert.Equal(tokenValidationParameters.NameClaimType, actualClaimsIdentity.NameClaimType);
            Assert.Equal(tokenValidationParameters.RoleClaimType, actualClaimsIdentity.RoleClaimType);

            if (useClaimsIdentity)
            {
                Assert.IsType<ClaimsIdentity>(actualClaimsIdentity);
            }
            else
            {
                Assert.IsType<CaseSensitiveClaimsIdentity>(actualClaimsIdentity);
                Assert.NotNull(((CaseSensitiveClaimsIdentity)actualClaimsIdentity).SecurityToken);
                Assert.Equal(jsonWebToken, ((CaseSensitiveClaimsIdentity)actualClaimsIdentity).SecurityToken);
            }

            AppContext.SetSwitch(AppContextSwitches.UseClaimsIdentityTypeSwitch, false);
        }

        [Fact]
        public void Create_FromDerivedTokenValidationParameters_HonorsSetSecurityToken()
        {
            var jsonWebToken = new JsonWebToken(Default.Jwt(Default.SecurityTokenDescriptor()));
            var tokenValidationParameters = new DerivedTokenValidationParameters(returnCaseSensitiveClaimsIdentityWithToken: true);
            tokenValidationParameters.AuthenticationType = "custom-authentication-type";
            tokenValidationParameters.NameClaimType = "custom-name";
            tokenValidationParameters.RoleClaimType = "custom-role";

            var actualClaimsIdentity = ClaimsIdentityFactory.Create(jsonWebToken, tokenValidationParameters, Default.Issuer);

            // The SecurityToken set in derived TokenValidationParameters is honored.
            Assert.IsType<CaseSensitiveClaimsIdentity>(actualClaimsIdentity);

            var securityToken = ((CaseSensitiveClaimsIdentity)actualClaimsIdentity).SecurityToken;
            Assert.NotNull(securityToken);
            Assert.IsType<TvpJsonWebToken>(securityToken);
            Assert.NotEqual(jsonWebToken, securityToken);

            Assert.Equal(tokenValidationParameters.AuthenticationType, actualClaimsIdentity.AuthenticationType);
            Assert.Equal(tokenValidationParameters.NameClaimType, actualClaimsIdentity.NameClaimType);
            Assert.Equal(tokenValidationParameters.RoleClaimType, actualClaimsIdentity.RoleClaimType);
        }

        [Theory]
        [InlineData(true)]
        [InlineData(false)]
        public void Create_FromDerivedTokenValidationParameters_ReturnsCorrectClaimsIdentity(bool tvpReturnsCaseSensitiveClaimsIdentityWithoutToken)
        {
            var jsonWebToken = new JsonWebToken(Default.Jwt(Default.SecurityTokenDescriptor()));
            var tokenValidationParameters = new DerivedTokenValidationParameters(returnCaseSensitiveClaimsIdentityWithoutToken: tvpReturnsCaseSensitiveClaimsIdentityWithoutToken);
            tokenValidationParameters.AuthenticationType = "custom-authentication-type";
            tokenValidationParameters.NameClaimType = "custom-name";
            tokenValidationParameters.RoleClaimType = "custom-role";

            var actualClaimsIdentity = ClaimsIdentityFactory.Create(jsonWebToken, tokenValidationParameters, Default.Issuer);

            Assert.IsType<CaseSensitiveClaimsIdentity>(actualClaimsIdentity);

            var securityToken = ((CaseSensitiveClaimsIdentity)actualClaimsIdentity).SecurityToken;
            Assert.NotNull(securityToken);
            Assert.Equal(jsonWebToken, securityToken);

            Assert.Equal(tokenValidationParameters.AuthenticationType, actualClaimsIdentity.AuthenticationType);
            Assert.Equal(tokenValidationParameters.NameClaimType, actualClaimsIdentity.NameClaimType);
            Assert.Equal(tokenValidationParameters.RoleClaimType, actualClaimsIdentity.RoleClaimType);
        }



        private class DerivedTokenValidationParameters : TokenValidationParameters
        {
            private bool _returnCaseSensitiveClaimsIdentityWithToken;
            private bool _returnCaseSensitiveClaimsIdentityWithoutToken;

            public DerivedTokenValidationParameters(bool returnCaseSensitiveClaimsIdentityWithToken = false, bool returnCaseSensitiveClaimsIdentityWithoutToken = false)
            {
                _returnCaseSensitiveClaimsIdentityWithToken = returnCaseSensitiveClaimsIdentityWithToken;
                _returnCaseSensitiveClaimsIdentityWithoutToken = returnCaseSensitiveClaimsIdentityWithoutToken;
            }

            public override ClaimsIdentity CreateClaimsIdentity(SecurityToken securityToken, string issuer)
            {
                if (_returnCaseSensitiveClaimsIdentityWithToken)
                {
                    return new CaseSensitiveClaimsIdentity(AuthenticationType, NameClaimType, RoleClaimType)
                    {
                        SecurityToken = new TvpJsonWebToken(Default.Jwt(Default.SecurityTokenDescriptor())),
                    };
                }

                if (_returnCaseSensitiveClaimsIdentityWithoutToken)
                {
                    return new CaseSensitiveClaimsIdentity(AuthenticationType, NameClaimType, RoleClaimType);
                }

                return new ClaimsIdentity(AuthenticationType, NameClaimType, RoleClaimType);
            }
        }

        private class TvpJsonWebToken : JsonWebToken
        {
            public TvpJsonWebToken(string jwtEncodedString) : base(jwtEncodedString)
            {
            }

            public TvpJsonWebToken(ReadOnlyMemory<char> encodedTokenMemory) : base(encodedTokenMemory)
            {
            }

            public TvpJsonWebToken(string header, string payload) : base(header, payload)
            {
            }
        }
    }
}
