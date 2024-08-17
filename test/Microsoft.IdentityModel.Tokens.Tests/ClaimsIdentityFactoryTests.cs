﻿// Copyright (c) Microsoft Corporation. All rights reserved.
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

            var actualClaimsIdentity = tokenValidationParameters.CreateClaimsIdentity(jsonWebToken, Default.Issuer);

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

            AppContextSwitches.ResetAllSwitches();
        }

        [Theory]
        [InlineData(true, true)]
        [InlineData(true, false)]
        [InlineData(false, false)]
        public void Create_FromDerivedTokenValidationParameters_ReturnsCorrectClaimsIdentity(bool tvpReturnsCaseSensitiveClaimsIdentity, bool tvpReturnsCaseSensitiveClaimsIdentityWithToken)
        {
            var jsonWebToken = new JsonWebToken(Default.Jwt(Default.SecurityTokenDescriptor()));
            var tokenValidationParameters = new DerivedTokenValidationParameters(tvpReturnsCaseSensitiveClaimsIdentity, tvpReturnsCaseSensitiveClaimsIdentityWithToken);
            tokenValidationParameters.AuthenticationType = "custom-authentication-type";
            tokenValidationParameters.NameClaimType = "custom-name";
            tokenValidationParameters.RoleClaimType = "custom-role";

            var actualClaimsIdentity = tokenValidationParameters.CreateClaimsIdentity(jsonWebToken, Default.Issuer);

            if (tvpReturnsCaseSensitiveClaimsIdentity)
            {
                Assert.IsType<CaseSensitiveClaimsIdentity>(actualClaimsIdentity);
                if (tvpReturnsCaseSensitiveClaimsIdentityWithToken)
                {
                    var securityToken = ((CaseSensitiveClaimsIdentity)actualClaimsIdentity).SecurityToken;
                    Assert.NotNull(securityToken);
                    Assert.IsType<TvpJsonWebToken>(securityToken);
                    Assert.NotEqual(jsonWebToken, securityToken);
                }
                else
                {
                    Assert.Null(((CaseSensitiveClaimsIdentity)actualClaimsIdentity).SecurityToken);
                }
            }
            else
            {
                Assert.IsType<ClaimsIdentity>(actualClaimsIdentity);
            }

            Assert.Equal(tokenValidationParameters.AuthenticationType, actualClaimsIdentity.AuthenticationType);
            Assert.Equal(tokenValidationParameters.NameClaimType, actualClaimsIdentity.NameClaimType);
            Assert.Equal(tokenValidationParameters.RoleClaimType, actualClaimsIdentity.RoleClaimType);
        }



        private class DerivedTokenValidationParameters : TokenValidationParameters
        {
            private bool _returnCaseSensitiveClaimsIdentity;
            private bool _returnCaseSensitiveClaimsIdentityWithToken;

            public DerivedTokenValidationParameters(bool returnCaseSensitiveClaimsIdentity = false, bool returnCaseSensitiveClaimsIdentityWithToken = false)
            {
                _returnCaseSensitiveClaimsIdentity = returnCaseSensitiveClaimsIdentity;
                _returnCaseSensitiveClaimsIdentityWithToken = returnCaseSensitiveClaimsIdentityWithToken;
            }

            public override ClaimsIdentity CreateClaimsIdentity(SecurityToken securityToken, string issuer)
            {
                if (_returnCaseSensitiveClaimsIdentity)
                {
                    if (_returnCaseSensitiveClaimsIdentityWithToken)
                    {
                        return new CaseSensitiveClaimsIdentity(AuthenticationType, NameClaimType, RoleClaimType)
                        {
                            SecurityToken = new TvpJsonWebToken(Default.Jwt(Default.SecurityTokenDescriptor())),
                        };
                    }
                    else
                    {
                        return new CaseSensitiveClaimsIdentity(AuthenticationType, NameClaimType, RoleClaimType);
                    }
                }

#pragma warning disable RS0030 // Do not used banned APIs
                return new ClaimsIdentity(AuthenticationType, NameClaimType, RoleClaimType);
#pragma warning restore RS0030 // Do not used banned APIs
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
