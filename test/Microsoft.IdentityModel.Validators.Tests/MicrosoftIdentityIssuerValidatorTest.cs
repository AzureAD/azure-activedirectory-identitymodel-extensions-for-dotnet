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
using System.Globalization;
using System.IdentityModel.Tokens.Jwt;
using System.Net.Http;
using System.Security.Claims;
using Microsoft.IdentityModel.JsonWebTokens;
using Microsoft.IdentityModel.Tokens;
using NSubstitute;
using Xunit;

#pragma warning disable CS3016 // Arrays as attribute arguments is not CLS-compliant

namespace Microsoft.IdentityModel.Validators.Tests
{
    public class MicrosoftIdentityIssuerValidatorTest
    {
        private readonly HttpClient _httpClient;

        public MicrosoftIdentityIssuerValidatorTest()
        {
            Logging.IdentityModelEventSource.ShowPII = true;
            _httpClient = new HttpClient();
        }

        private AadIssuerValidator CreateIssuerValidator(string authority)
        {
            return AadIssuerValidator.GetAadIssuerValidator(authority, _httpClient);
        }

        [Fact]
        public void GetIssuerValidator_NullOrEmptyAuthority_ThrowsException()
        {
            Assert.Throws<ArgumentNullException>(ValidatorConstants.AadAuthority, () => CreateIssuerValidator(string.Empty));

            Assert.Throws<ArgumentNullException>(ValidatorConstants.AadAuthority, () => CreateIssuerValidator(null));
        }

        [Fact]
        public void GetIssuerValidator_InvalidAuthority_ReturnsValidatorBasedOnFallbackAuthority()
        {
            Assert.NotNull(CreateIssuerValidator(ValidatorConstants.InvalidAuthorityFormat));
        }

        [Fact]
        public void GetIssuerValidator_CommonAuthorityInAliases_ReturnsValidator()
        {
            var authorityInAliases = ValidatorConstants.AuthorityCommonTenantWithV2;

            var validator = CreateIssuerValidator(authorityInAliases);

            Assert.NotNull(validator);
        }

        [Fact]
        public void GetIssuerValidator_OrganizationsAuthorityInAliases_ReturnsValidator()
        {
            var authorityInAliases = ValidatorConstants.AuthorityOrganizationsWithV2;

            var validator = CreateIssuerValidator(authorityInAliases);

            Assert.NotNull(validator);
        }

        [Fact]
        public void GetIssuerValidator_B2cAuthorityNotInAliases_ReturnsValidator()
        {
            var authorityNotInAliases = ValidatorConstants.B2CAuthorityWithV2;

            var validator = CreateIssuerValidator(authorityNotInAliases);

            Assert.NotNull(validator);
        }

        [Fact]
        public void GetIssuerValidator_CachedAuthority_ReturnsCachedValidator()
        {
            var authorityNotInAliases = ValidatorConstants.AuthorityWithTenantSpecifiedWithV2;

            var validator1 = CreateIssuerValidator(authorityNotInAliases);
            var validator2 = CreateIssuerValidator(authorityNotInAliases);

            Assert.Same(validator1, validator2);
        }

        [Fact]
        public void Validate_NullOrEmptyParameters_ThrowsException()
        {
            var validator = new AadIssuerValidator(_httpClient, ValidatorConstants.AadIssuer);
            var jwtSecurityToken = new JwtSecurityToken();
            var validationParams = new TokenValidationParameters();

            Assert.Throws<ArgumentNullException>(ValidatorConstants.ActualIssuer, () => validator.Validate(null, jwtSecurityToken, validationParams));

            Assert.Throws<ArgumentNullException>(ValidatorConstants.ActualIssuer, () => validator.Validate(string.Empty, jwtSecurityToken, validationParams));

            Assert.Throws<ArgumentNullException>(ValidatorConstants.SecurityToken, () => validator.Validate(ValidatorConstants.AadIssuer, null, validationParams));

            Assert.Throws<ArgumentNullException>(ValidatorConstants.ValidationParameters, () => validator.Validate(ValidatorConstants.AadIssuer, jwtSecurityToken, null));
        }

        [Fact]
        public void Validate_NullOrEmptyTenantId_ThrowsException()
        {
            var validator = new AadIssuerValidator(_httpClient, ValidatorConstants.AadIssuer);
            var jwtSecurityToken = new JwtSecurityToken();
            var jsonWebToken = new JsonWebToken($"{{}}", $"{{}}");
            var securityToken = Substitute.For<SecurityToken>();
            var validationParameters = new TokenValidationParameters();

            var exception = Assert.Throws<SecurityTokenInvalidIssuerException>(() => validator.Validate(ValidatorConstants.AadIssuer, jwtSecurityToken, validationParameters));
            Assert.Equal(LogMessages.IDX40105, exception.Message);

            exception = Assert.Throws<SecurityTokenInvalidIssuerException>(() => validator.Validate(ValidatorConstants.AadIssuer, jsonWebToken, validationParameters));
            Assert.Equal(LogMessages.IDX40105, exception.Message);

            exception = Assert.Throws<SecurityTokenInvalidIssuerException>(() => validator.Validate(ValidatorConstants.AadIssuer, securityToken, validationParameters));
            Assert.Equal(LogMessages.IDX40105, exception.Message);
        }

        [Theory]
        [InlineData(ValidatorConstants.ClaimNameTid, ValidatorConstants.AuthorityCommonTenant, ValidatorConstants.AadIssuer)]
        [InlineData(ValidatorConstants.TenantId, ValidatorConstants.AuthorityCommonTenant, ValidatorConstants.AadIssuer)]
        [InlineData(ValidatorConstants.ClaimNameTid, ValidatorConstants.UsGovTenantId, ValidatorConstants.UsGovIssuer)]
        [InlineData(ValidatorConstants.TenantId, ValidatorConstants.UsGovTenantId, ValidatorConstants.UsGovIssuer)]
        public void Validate_IssuerMatchedInValidIssuer_ReturnsIssuer(string tidClaimType, string tenantId, string issuer)
        {
            var validator = new AadIssuerValidator(_httpClient, issuer);
            var tidClaim = new Claim(tidClaimType, tenantId);

            var issClaim = new Claim(ValidatorConstants.ClaimNameIss, issuer);
            var jwtSecurityToken = new JwtSecurityToken(issuer: issuer, claims: new[] { issClaim, tidClaim });

            validator.AadIssuerV2 = issuer;

            var actualIssuer = validator.Validate(issuer, jwtSecurityToken, new TokenValidationParameters() { ValidIssuer = issuer });

            Assert.Equal(issuer, actualIssuer);
        }

        [Theory]
        [InlineData(ValidatorConstants.ClaimNameTid, ValidatorConstants.TenantIdAsGuid, ValidatorConstants.AadIssuer)]
        [InlineData(ValidatorConstants.TenantId, ValidatorConstants.TenantIdAsGuid, ValidatorConstants.AadIssuer)]
        [InlineData(ValidatorConstants.ClaimNameTid, ValidatorConstants.TenantIdAsGuid, ValidatorConstants.V1Issuer)]
        [InlineData(ValidatorConstants.TenantId, ValidatorConstants.TenantIdAsGuid, ValidatorConstants.V1Issuer)]
        public void Validate_NoHttpclientFactory_ReturnsIssuer(string tidClaimType, string tenantId, string issuer)
        {
            var validator = new AadIssuerValidator(null, issuer);
            var tidClaim = new Claim(tidClaimType, tenantId);

            var issClaim = new Claim(ValidatorConstants.ClaimNameIss, issuer);
            var jwtSecurityToken = new JwtSecurityToken(issuer: issuer, claims: new[] { issClaim, tidClaim });

            Assert.Equal(issuer, validator.Validate(issuer, jwtSecurityToken, new TokenValidationParameters()));
        }

        [Theory]
        [InlineData(ValidatorConstants.ClaimNameTid, ValidatorConstants.TenantIdAsGuid, ValidatorConstants.V1Issuer)]
        [InlineData(ValidatorConstants.TenantId, ValidatorConstants.TenantIdAsGuid, ValidatorConstants.V1Issuer)]
        public void Validate_IssuerMatchedInValidV1Issuer_ReturnsIssuer(string tidClaimType, string tenantId, string issuer)
        {
            var validator = new AadIssuerValidator(_httpClient, issuer);
            var tidClaim = new Claim(tidClaimType, tenantId);

            var issClaim = new Claim(ValidatorConstants.ClaimNameIss, issuer);
            var jwtSecurityToken = new JwtSecurityToken(issuer: issuer, claims: new[] { issClaim, tidClaim });

            validator.AadIssuerV1 = issuer;

            var actualIssuer = validator.Validate(issuer, jwtSecurityToken, new TokenValidationParameters() { ValidIssuer = issuer });

            Assert.Equal(issuer, actualIssuer);

            var actualIssuers = validator.Validate(issuer, jwtSecurityToken, new TokenValidationParameters() { ValidIssuers = new[] { issuer } });

            Assert.Equal(issuer, actualIssuers);
        }

        [Theory]
        [InlineData(ValidatorConstants.ClaimNameTid)]
        [InlineData(ValidatorConstants.TenantId)]
        public void Validate_IssuerMatchedInValidIssuers_ReturnsIssuer(string tidClaimType)
        {
            var validator = new AadIssuerValidator(_httpClient, ValidatorConstants.AadIssuer);
            var tidClaim = new Claim(tidClaimType, ValidatorConstants.TenantIdAsGuid);

            var issClaim = new Claim(ValidatorConstants.ClaimNameIss, ValidatorConstants.AadIssuer);
            var jwtSecurityToken = new JwtSecurityToken(issuer: ValidatorConstants.AadIssuer, claims: new[] { issClaim, tidClaim });

            var actualIssuers = validator.Validate(ValidatorConstants.AadIssuer, jwtSecurityToken, new TokenValidationParameters() { ValidIssuers = new[] { ValidatorConstants.AadIssuer } });

            Assert.Equal(ValidatorConstants.AadIssuer, actualIssuers);

            var actualIssuer = validator.Validate(ValidatorConstants.AadIssuer, jwtSecurityToken, new TokenValidationParameters() { ValidIssuer = ValidatorConstants.AadIssuer });

            Assert.Equal(ValidatorConstants.AadIssuer, actualIssuer);
        }

        [Theory]
        [InlineData(ValidatorConstants.ClaimNameTid)]
        [InlineData(ValidatorConstants.TenantId)]
        public void Validate_IssuerNotInTokenValidationParameters_ReturnsIssuer(string tidClaimType)
        {
            var validator = new AadIssuerValidator(_httpClient, ValidatorConstants.AadIssuer);
            var tidClaim = new Claim(tidClaimType, ValidatorConstants.TenantIdAsGuid);

            var issClaim = new Claim(ValidatorConstants.ClaimNameIss, ValidatorConstants.AadIssuer);
            var jwtSecurityToken = new JwtSecurityToken(issuer: ValidatorConstants.AadIssuer, claims: new[] { issClaim, tidClaim });

            var actualIssuer = validator.Validate(ValidatorConstants.AadIssuer, jwtSecurityToken, new TokenValidationParameters());

            Assert.Equal(ValidatorConstants.AadIssuer, actualIssuer);
        }

        [Theory]
        [InlineData(ValidatorConstants.ClaimNameTid)]
        [InlineData(ValidatorConstants.TenantId)]
        public void Validate_V1IssuerNotInTokenValidationParameters_ReturnsV1Issuer(string tidClaimType)
        {
            var validator = new AadIssuerValidator(_httpClient, ValidatorConstants.V1Issuer);
            var tidClaim = new Claim(tidClaimType, ValidatorConstants.TenantIdAsGuid);

            var issClaim = new Claim(ValidatorConstants.ClaimNameIss, ValidatorConstants.V1Issuer);
            var jwtSecurityToken = new JwtSecurityToken(issuer: ValidatorConstants.V1Issuer, claims: new[] { issClaim, tidClaim });

            var actualIssuer = validator.Validate(ValidatorConstants.V1Issuer, jwtSecurityToken, new TokenValidationParameters());

            Assert.Equal(ValidatorConstants.V1Issuer, actualIssuer);
        }

        [Fact]
        public void Validate_TenantIdInIssuerNotInToken_ReturnsIssuer()
        {
            var validator = new AadIssuerValidator(_httpClient, ValidatorConstants.AadIssuer);
            var issClaim = new Claim(ValidatorConstants.ClaimNameIss, ValidatorConstants.AadIssuer);
            var jwtSecurityToken = new JwtSecurityToken(issuer: ValidatorConstants.AadIssuer, claims: new[] { issClaim });

            var actualIssuer = validator.Validate(ValidatorConstants.AadIssuer, jwtSecurityToken, new TokenValidationParameters() { ValidIssuer = ValidatorConstants.AadIssuer });

            Assert.Equal(ValidatorConstants.AadIssuer, actualIssuer);
        }

        [Fact]
        public void Validate_TidClaimInToken_ReturnsIssuer()
        {
            var validator = new AadIssuerValidator(_httpClient, ValidatorConstants.AadIssuer);
            var tidClaim = new Claim(ValidatorConstants.ClaimNameTid, ValidatorConstants.TenantIdAsGuid);
            var issClaim = new Claim(ValidatorConstants.ClaimNameIss, ValidatorConstants.AadIssuer);
            var jwtSecurityToken = new JwtSecurityToken(issuer: ValidatorConstants.AadIssuer, claims: new[] { issClaim, tidClaim });
            var jsonWebToken = new JsonWebToken($"{{}}", $"{{\"{ValidatorConstants.ClaimNameIss}\":\"{ValidatorConstants.AadIssuer}\",\"{ValidatorConstants.ClaimNameTid}\":\"{ValidatorConstants.TenantIdAsGuid}\"}}");

            var actualIssuer = validator.Validate(ValidatorConstants.AadIssuer, jwtSecurityToken, new TokenValidationParameters() { ValidIssuer = ValidatorConstants.AadIssuer });

            Assert.Equal(ValidatorConstants.AadIssuer, actualIssuer);

            actualIssuer = validator.Validate(ValidatorConstants.AadIssuer, jsonWebToken, new TokenValidationParameters() { ValidIssuer = ValidatorConstants.AadIssuer });

            Assert.Equal(ValidatorConstants.AadIssuer, actualIssuer);
        }

        // Regression test for https://github.com/Azure-Samples/active-directory-dotnet-native-aspnetcore-v2/issues/68
        // Similar to Validate_NotMatchedToMultipleIssuers_ThrowsException but uses B2C values
        [Fact]
        public void Validate_InvalidIssuerToValidate_ThrowsException()
        {
            string invalidIssuerToValidate = $"https://badissuer/{ValidatorConstants.TenantIdAsGuid}/v2.0";
            AadIssuerValidator validator = new AadIssuerValidator(_httpClient, invalidIssuerToValidate);
            Claim issClaim = new Claim(ValidatorConstants.ClaimNameIss, ValidatorConstants.AadIssuer);
            Claim tidClaim = new Claim(ValidatorConstants.ClaimNameTid, ValidatorConstants.TenantIdAsGuid);
            JwtSecurityToken jwtSecurityToken = new JwtSecurityToken(issuer: ValidatorConstants.AadIssuer, claims: new[] { issClaim, tidClaim });
            var expectedErrorMessage = string.Format(
                    CultureInfo.InvariantCulture,
                    LogMessages.IDX40103,
                    invalidIssuerToValidate);

            var exception = Assert.Throws<SecurityTokenInvalidIssuerException>(() =>
                validator.Validate(invalidIssuerToValidate, jwtSecurityToken, new TokenValidationParameters() { ValidIssuers = new[] { ValidatorConstants.AadIssuer } }));
            Assert.Equal(expectedErrorMessage, exception.Message);
        }

        // Similar to Validate_TenantIdInIssuerNotInToken_ReturnsIssuer but uses
        // GetIssuerValidator instead of the constructor and B2C values
        [Fact]
        public void Validate_FromB2CAuthority_WithNoTidClaim_ValidateSuccessfully()
        {
            Claim issClaim = new Claim(ValidatorConstants.ClaimNameIss, ValidatorConstants.B2CIssuer);
            Claim tfpClaim = new Claim(ValidatorConstants.ClaimNameTfp, ValidatorConstants.B2CSignUpSignInUserFlow);
            JwtSecurityToken jwtSecurityToken = new JwtSecurityToken(issuer: ValidatorConstants.B2CIssuer, claims: new[] { issClaim, tfpClaim });

            AadIssuerValidator validator = CreateIssuerValidator(ValidatorConstants.B2CAuthorityWithV2);

            validator.Validate(
                ValidatorConstants.B2CIssuer,
                jwtSecurityToken,
                new TokenValidationParameters()
                {
                    ValidIssuers = new[] { ValidatorConstants.B2CIssuer },
                });
        }

        // Similar to Validate_TidClaimInToken_ReturnsIssuer but uses
        // GetIssuerValidator instead of the constructor and B2C values
        [Fact]
        public void Validate_FromB2CAuthority_WithTidClaim_ValidateSuccessfully()
        {
            Claim issClaim = new Claim(ValidatorConstants.ClaimNameIss, ValidatorConstants.B2CIssuer);
            Claim tfpClaim = new Claim(ValidatorConstants.ClaimNameTfp, ValidatorConstants.B2CSignUpSignInUserFlow);
            Claim tidClaim = new Claim(ValidatorConstants.ClaimNameTid, ValidatorConstants.B2CTenantAsGuid);
            JwtSecurityToken jwtSecurityToken = new JwtSecurityToken(issuer: ValidatorConstants.B2CIssuer, claims: new[] { issClaim, tfpClaim, tidClaim });

            AadIssuerValidator validator = CreateIssuerValidator(ValidatorConstants.B2CAuthorityWithV2);

            validator.Validate(
                ValidatorConstants.B2CIssuer,
                jwtSecurityToken,
                new TokenValidationParameters()
                {
                    ValidIssuers = new[] { ValidatorConstants.B2CIssuer },
                });
        }

        // Similar to Validate_NotMatchedIssuer_ThrowsException and Validate_NotMatchedToMultipleIssuers_ThrowsException but uses
        // GetIssuerValidator instead of the constructor and B2C values
        [Fact]
        public void Validate_FromB2CAuthority_InvalidIssuer_Fails()
        {
            Claim issClaim = new Claim(ValidatorConstants.ClaimNameIss, ValidatorConstants.B2CIssuer2);
            Claim tfpClaim = new Claim(ValidatorConstants.ClaimNameTfp, ValidatorConstants.B2CSignUpSignInUserFlow);
            JwtSecurityToken jwtSecurityToken = new JwtSecurityToken(issuer: ValidatorConstants.B2CIssuer2, claims: new[] { issClaim, tfpClaim });

            AadIssuerValidator validator = CreateIssuerValidator(ValidatorConstants.B2CAuthorityWithV2);

            Assert.Throws<SecurityTokenInvalidIssuerException>(() =>
                validator.Validate(
                    ValidatorConstants.B2CIssuer2,
                    jwtSecurityToken,
                    new TokenValidationParameters()
                    {
                        ValidIssuers = new[] { ValidatorConstants.B2CIssuer },
                    }));
        }

        // Similar to Validate_NotMatchedTenantIds_ThrowsException but uses
        // GetIssuerValidator instead of the constructor and B2C values
        [Fact]
        public void Validate_FromB2CAuthority_InvalidIssuerTid_Fails()
        {
            string issuerWithInvalidTid = ValidatorConstants.B2CInstance + "/" + ValidatorConstants.TenantIdAsGuid + "/v2.0";
            Claim issClaim = new Claim(ValidatorConstants.ClaimNameIss, issuerWithInvalidTid);
            Claim tfpClaim = new Claim(ValidatorConstants.ClaimNameTfp, ValidatorConstants.B2CSignUpSignInUserFlow);
            JwtSecurityToken jwtSecurityToken = new JwtSecurityToken(issuer: issuerWithInvalidTid, claims: new[] { issClaim, tfpClaim });

            AadIssuerValidator validator = CreateIssuerValidator(ValidatorConstants.B2CAuthorityWithV2);

            Assert.Throws<SecurityTokenInvalidIssuerException>(() =>
                validator.Validate(
                    issuerWithInvalidTid,
                    jwtSecurityToken,
                    new TokenValidationParameters()
                    {
                        ValidIssuers = new[] { ValidatorConstants.B2CIssuer },
                    }));
        }

        // Similar to Validate_IssuerMatchedInValidIssuers_ReturnsIssuer but uses
        // GetIssuerValidator instead of the constructor and B2C values
        [Fact]
        public void Validate_FromCustomB2CAuthority_ValidateSuccessfully()
        {
            Claim issClaim = new Claim(ValidatorConstants.ClaimNameIss, ValidatorConstants.B2CCustomDomainIssuer);
            Claim tfpClaim = new Claim(ValidatorConstants.ClaimNameTfp, ValidatorConstants.B2CCustomDomainUserFlow);
            JwtSecurityToken jwtSecurityToken = new JwtSecurityToken(issuer: ValidatorConstants.B2CCustomDomainIssuer, claims: new[] { issClaim, tfpClaim });

            AadIssuerValidator validator = CreateIssuerValidator(ValidatorConstants.B2CCustomDomainAuthorityWithV2);

            validator.Validate(
                ValidatorConstants.B2CCustomDomainIssuer,
                jwtSecurityToken,
                new TokenValidationParameters()
                {
                    ValidIssuers = new[] { ValidatorConstants.B2CCustomDomainIssuer },
                });
        }

        [Fact]
        public void Validate_FromB2CAuthority_WithTfpIssuer_ThrowsException()
        {
            Claim issClaim = new Claim(ValidatorConstants.ClaimNameIss, ValidatorConstants.B2CIssuerTfp);
            JwtSecurityToken jwtSecurityToken = new JwtSecurityToken(issuer: ValidatorConstants.B2CIssuerTfp, claims: new[] { issClaim });

            AadIssuerValidator validator = CreateIssuerValidator(ValidatorConstants.B2CAuthorityWithV2);

            var exception = Assert.Throws<SecurityTokenInvalidIssuerException>(() =>
                validator.Validate(
                    ValidatorConstants.B2CIssuerTfp,
                    jwtSecurityToken,
                    new TokenValidationParameters()
                    {
                        ValidIssuers = new[] { ValidatorConstants.B2CIssuerTfp },
                    }));
            Assert.Equal(LogMessages.IDX40104, exception.Message);
        }
    }
}

#pragma warning restore CS3016 // Arrays as attribute arguments is not CLS-compliant
