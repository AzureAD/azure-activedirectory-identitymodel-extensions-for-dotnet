// Copyright (c) Microsoft Corporation. All rights reserved.
// Licensed under the MIT License.

using System;
using System.Collections.Generic;
using System.Globalization;
using System.IdentityModel.Tokens.Jwt;
using System.Net;
using System.Net.Http;
using System.Security.Claims;
using System.Threading;
using System.Threading.Tasks;
using Microsoft.IdentityModel.JsonWebTokens;
using Microsoft.IdentityModel.Protocols.OpenIdConnect;
using Microsoft.IdentityModel.TestUtils;
using Microsoft.IdentityModel.Tokens;
using Microsoft.IdentityModel.Tokens.Experimental;
using NSubstitute;
using Xunit;

namespace Microsoft.IdentityModel.Validators.Tests
{
    public class MicrosoftIdentityIssuerValidatorTestSync
    {
        private readonly HttpClient _httpClient;

        // URL markers and fixtures for the offline metadata-mocking tests below. The mock handler routes
        // requests by these path fragments, and PlaceholderJwksUri is the jwks_uri advertised in the mock
        // metadata so the key-set fetch is routed back to the handler. Issuer validation itself only reads
        // the metadata issuer ({tenantid} template) and JwksUri.
        private const string OpenIdConfigurationPath = "/.well-known/openid-configuration";
        private const string DiscoveryPathMarker = "/discovery/";
        private const string KeysPathMarker = "/keys";
        private const string UnexpectedUrlMessagePrefix = "Unexpected URL in offline test: ";
        private const string PlaceholderJwksUri = "https://example.com/discovery/keys";

        public MicrosoftIdentityIssuerValidatorTestSync()
        {
            Logging.IdentityModelEventSource.ShowPII = true;
            _httpClient = new HttpClient();
            AadIssuerValidator.s_issuerValidators.Clear();
        }

        private AadIssuerValidator CreateIssuerValidator(string authority)
        {
            return AadIssuerValidator.GetAadIssuerValidator(authority, _httpClient);
        }

        private AadIssuerValidator CreateIssuerValidatorWithConfigurationProvider(string authority, Func<string, BaseConfigurationManager> configurationProvider)
        {
            return AadIssuerValidator.GetAadIssuerValidator(authority, _httpClient, configurationProvider);
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
        public void GetIssuerValidator_V1Authority()
        {
            var context = new CompareContext();
            var authorityInAliases = ValidatorConstants.AuthorityV1;

            var validator = CreateIssuerValidator(authorityInAliases);

            IdentityComparer.AreEqual(ValidatorConstants.AuthorityV1, validator.AadAuthorityV1, context);
            IdentityComparer.AreEqual(ValidatorConstants.AuthorityCommonTenantWithV2, validator.AadAuthorityV2, context);
            IdentityComparer.AreEqual(ProtocolVersion.V1, validator.AadAuthorityVersion, context);
            TestUtilities.AssertFailIfErrors(context);
        }

        [Fact]
        public void GetIssuerValidator_TwoTenants()
        {
            var context = new CompareContext();
            var validator = CreateIssuerValidator(ValidatorConstants.AuthorityV1);

            IdentityComparer.AreEqual(ValidatorConstants.AuthorityV1, validator.AadAuthorityV1, context);
            IdentityComparer.AreEqual(ValidatorConstants.AuthorityCommonTenantWithV2, validator.AadAuthorityV2, context);
            IdentityComparer.AreEqual(ProtocolVersion.V1, validator.AadAuthorityVersion, context);

            validator = CreateIssuerValidator(ValidatorConstants.AuthorityWithTenantSpecified);
            IdentityComparer.AreEqual(ValidatorConstants.AuthorityWithTenantSpecified, validator.AadAuthorityV1, context);
            IdentityComparer.AreEqual(ValidatorConstants.AuthorityWithTenantSpecifiedWithV2, validator.AadAuthorityV2, context);
            IdentityComparer.AreEqual(ProtocolVersion.V1, validator.AadAuthorityVersion, context);

            TestUtilities.AssertFailIfErrors(context);
        }

        [Fact]
        public void GetIssuerValidator_CommonAuthorityInAliases()
        {
            var context = new CompareContext();
            var authorityInAliases = ValidatorConstants.AuthorityCommonTenantWithV2;

            var validator = CreateIssuerValidator(authorityInAliases);

            IdentityComparer.AreEqual(ValidatorConstants.AuthorityV1, validator.AadAuthorityV1, context);
            IdentityComparer.AreEqual(ValidatorConstants.AuthorityCommonTenantWithV2, validator.AadAuthorityV2, context);
            IdentityComparer.AreEqual(ProtocolVersion.V2, validator.AadAuthorityVersion, context);
            TestUtilities.AssertFailIfErrors(context);
        }

        [Fact]
        public void GetIssuerValidator_OrganizationsAuthorityInAliases()
        {
            var context = new CompareContext();
            var authorityInAliases = ValidatorConstants.AuthorityOrganizationsWithV2;

            var validator = CreateIssuerValidator(authorityInAliases);

            IdentityComparer.AreEqual(ValidatorConstants.AuthorityV1, validator.AadAuthorityV1, context);
            IdentityComparer.AreEqual(ValidatorConstants.AuthorityOrganizationsWithV2, validator.AadAuthorityV2, context);
            IdentityComparer.AreEqual(ProtocolVersion.V2, validator.AadAuthorityVersion, context);
            TestUtilities.AssertFailIfErrors(context);
        }

        [Fact]
        public void GetIssuerValidator_B2cAuthorityNotInAliases()
        {
            var context = new CompareContext();
            var authorityNotInAliases = ValidatorConstants.B2CAuthorityWithV2;

            var validator = CreateIssuerValidator(authorityNotInAliases);
            IdentityComparer.AreEqual(ValidatorConstants.B2CAuthority, validator.AadAuthorityV1, context);
            IdentityComparer.AreEqual(ValidatorConstants.B2CAuthorityWithV2, validator.AadAuthorityV2, context);
            IdentityComparer.AreEqual(ProtocolVersion.V2, validator.AadAuthorityVersion, context);
            TestUtilities.AssertFailIfErrors(context);
        }

        [Fact]
        public void GetIssuerValidator_CachedAuthority_ReturnsCachedValidator()
        {
            var context = new CompareContext();
            var authorityNotInAliases = ValidatorConstants.AuthorityWithTenantSpecifiedWithV2;

            var validator1 = CreateIssuerValidator(authorityNotInAliases);
            var validator2 = CreateIssuerValidator(authorityNotInAliases);

            IdentityComparer.AreEqual(validator1, validator2, context);
            TestUtilities.AssertFailIfErrors(context);
        }

        [Fact]
        public void Validate_NullOrEmptyParameters_ThrowsException()
        {
            var context = new CompareContext();
            var validator = new AadIssuerValidator(_httpClient, ValidatorConstants.AadIssuer);
            var jwtSecurityToken = new JwtSecurityToken();
            var validationParams = new TokenValidationParameters();

            Assert.Throws<ArgumentNullException>(ValidatorConstants.Issuer, () => validator.Validate(null, jwtSecurityToken, validationParams));
            Assert.Throws<ArgumentNullException>(() => ValidateIssuerSync(null, jwtSecurityToken, validator));

            var exception = Assert.Throws<SecurityTokenInvalidIssuerException>(() => validator.Validate(string.Empty, jwtSecurityToken, validationParams));
            ValidationResult<ValidatedIssuer, IssuerValidationError> validationResult = ValidateIssuerSync(string.Empty, jwtSecurityToken, validator);
            Assert.False(validationResult.Succeeded);

            IdentityComparer.AreEqual(LogMessages.IDX40003, exception.Message);

            Assert.Throws<ArgumentNullException>(ValidatorConstants.SecurityToken, () => validator.Validate(ValidatorConstants.AadIssuer, null, validationParams));
            Assert.Throws<ArgumentNullException>(() => ValidateIssuerSync(ValidatorConstants.AadIssuer, null, validator));

            Assert.Throws<ArgumentNullException>(ValidatorConstants.ValidationParameters, () => validator.Validate(ValidatorConstants.AadIssuer, jwtSecurityToken, null));

            Assert.Throws<ArgumentNullException>(() => validator.ValidateIssuerSync(ValidatorConstants.AadIssuer, jwtSecurityToken, null, new Tokens.CallContext(), CancellationToken.None));

            TestUtilities.AssertFailIfErrors(context);
        }

        [Fact]
        public void Validate_NullOrEmptyTenantId_ThrowsException()
        {
            var context = new CompareContext();
            var validator = new AadIssuerValidator(_httpClient, ValidatorConstants.AadIssuer);
            var jwtSecurityToken = new JwtSecurityToken();
            var jsonWebToken = new JsonWebToken($"{{}}", $"{{}}");
            var securityToken = Substitute.For<SecurityToken>();
            var validationParameters = new TokenValidationParameters();

            var exception = Assert.Throws<SecurityTokenInvalidIssuerException>(() => validator.Validate(ValidatorConstants.AadIssuer, jwtSecurityToken, validationParameters));
            IdentityComparer.AreEqual(LogMessages.IDX40003, exception.Message, context);

            exception = Assert.Throws<SecurityTokenInvalidIssuerException>(() => validator.Validate(ValidatorConstants.AadIssuer, jsonWebToken, validationParameters));
            IdentityComparer.AreEqual(LogMessages.IDX40003, exception.Message, context);

            exception = Assert.Throws<SecurityTokenInvalidIssuerException>(() => validator.Validate(ValidatorConstants.AadIssuer, securityToken, validationParameters));
            IdentityComparer.AreEqual(LogMessages.IDX40003, exception.Message, context);
            TestUtilities.AssertFailIfErrors(context);
        }

        [Theory]
        [InlineData(ValidatorConstants.ClaimNameTid, ValidatorConstants.AuthorityCommonTenant, ValidatorConstants.AadIssuer, false)]
        [InlineData(ValidatorConstants.TenantId, ValidatorConstants.AuthorityCommonTenant, ValidatorConstants.AadIssuer, false)]
        [InlineData(ValidatorConstants.ClaimNameTid, ValidatorConstants.UsGovTenantId, ValidatorConstants.UsGovIssuer, false)]
        [InlineData(ValidatorConstants.TenantId, ValidatorConstants.UsGovTenantId, ValidatorConstants.UsGovIssuer, false)]
        [InlineData(ValidatorConstants.ClaimNameTid, ValidatorConstants.AuthorityCommonTenant, ValidatorConstants.AadIssuer, true)]
        [InlineData(ValidatorConstants.TenantId, ValidatorConstants.AuthorityCommonTenant, ValidatorConstants.AadIssuer, true)]
        [InlineData(ValidatorConstants.ClaimNameTid, ValidatorConstants.UsGovTenantId, ValidatorConstants.UsGovIssuer, true)]
        [InlineData(ValidatorConstants.TenantId, ValidatorConstants.UsGovTenantId, ValidatorConstants.UsGovIssuer, true)]
        public void Validate_IssuerMatchedInValidIssuer_ReturnsIssuer(string tidClaimType, string tenantId, string issuer, bool useConfigurationManagerProvider)
        {
            var context = new CompareContext();
            AadIssuerValidator validator = null;
            if (!useConfigurationManagerProvider)
                validator = new AadIssuerValidator(_httpClient, issuer);
            else
                validator = new AadIssuerValidator(_httpClient, issuer, x => null);

            var tidClaim = new Claim(tidClaimType, tenantId);
            var issClaim = new Claim(ValidatorConstants.ClaimNameIss, issuer);
            var jwtSecurityToken = new JwtSecurityToken(issuer: issuer, claims: new[] { issClaim, tidClaim });

            var actualIssuer = validator.Validate(issuer, jwtSecurityToken, new TokenValidationParameters() { ValidIssuer = issuer });
            ValidationResult<ValidatedIssuer, IssuerValidationError> validationResult = ValidateIssuerSync(issuer, issuer, jwtSecurityToken, validator);

            IdentityComparer.AreEqual(validationResult.Result.Issuer, actualIssuer, context);
            IdentityComparer.AreEqual(issuer, actualIssuer, context);
            TestUtilities.AssertFailIfErrors(context);
        }

#if NET5_0_OR_GREATER
        [Theory]
        [InlineData(ValidatorConstants.ClaimNameTid, ValidatorConstants.TenantIdAsGuid, ValidatorConstants.AadIssuer)]
        [InlineData(ValidatorConstants.TenantId, ValidatorConstants.TenantIdAsGuid, ValidatorConstants.AadIssuer)]
        [InlineData(ValidatorConstants.ClaimNameTid, ValidatorConstants.TenantIdAsGuid, ValidatorConstants.V1Issuer)]
        [InlineData(ValidatorConstants.TenantId, ValidatorConstants.TenantIdAsGuid, ValidatorConstants.V1Issuer)]
        public void Validate_NoHttpclientFactory_ReturnsIssuer(string tidClaimType, string tenantId, string issuer)
        {
            var context = new CompareContext();
            var validator = new AadIssuerValidator(null, issuer);
            var tidClaim = new Claim(tidClaimType, tenantId);

            var issClaim = new Claim(ValidatorConstants.ClaimNameIss, issuer);
            var jwtSecurityToken = new JwtSecurityToken(issuer: issuer, claims: new[] { issClaim, tidClaim });

            MockConfigurationManager<OpenIdConnectConfiguration> configurationManager =
                new MockConfigurationManager<OpenIdConnectConfiguration>(new OpenIdConnectConfiguration() { Issuer = issuer });

            var tokenValidationParams = new TokenValidationParameters() { ConfigurationManager = configurationManager };
            ValidationResult<ValidatedIssuer, IssuerValidationError> validationResult = ValidateIssuerSync(issuer, configurationManager, jwtSecurityToken, validator);

            IdentityComparer.AreEqual(issuer, validationResult.Result.Issuer, context);
            IdentityComparer.AreEqual(issuer, validator.Validate(issuer, jwtSecurityToken, tokenValidationParams), context);
            TestUtilities.AssertFailIfErrors(context);
        }
#endif

        [Theory]
        [InlineData(ValidatorConstants.ClaimNameTid, ValidatorConstants.TenantIdAsGuid, ValidatorConstants.V1Issuer, false)]
        [InlineData(ValidatorConstants.TenantId, ValidatorConstants.TenantIdAsGuid, ValidatorConstants.V1Issuer, false)]
        [InlineData(ValidatorConstants.ClaimNameTid, ValidatorConstants.TenantIdAsGuid, ValidatorConstants.V1Issuer, true)]
        [InlineData(ValidatorConstants.TenantId, ValidatorConstants.TenantIdAsGuid, ValidatorConstants.V1Issuer, true)]
        public void Validate_IssuerMatchedInValidV1Issuer_ReturnsIssuer(string tidClaimType, string tenantId, string issuer, bool useConfigurationProvider)
        {
            var context = new CompareContext();

            AadIssuerValidator validator = null;
            if (useConfigurationProvider == false)
                validator = new AadIssuerValidator(_httpClient, issuer);
            else
                validator = new AadIssuerValidator(_httpClient, issuer, x => null);

            var tidClaim = new Claim(tidClaimType, tenantId);

            var issClaim = new Claim(ValidatorConstants.ClaimNameIss, issuer);
            var jwtSecurityToken = new JwtSecurityToken(issuer: issuer, claims: new[] { issClaim, tidClaim });

            var actualIssuer = validator.Validate(issuer, jwtSecurityToken, new TokenValidationParameters() { ValidIssuer = issuer });
            ValidationResult<ValidatedIssuer, IssuerValidationError> validationResult = ValidateIssuerSync(issuer, issuer, jwtSecurityToken, validator);

            IdentityComparer.AreEqual(issuer, validationResult.Result.Issuer, context);
            IdentityComparer.AreEqual(issuer, actualIssuer, context);

            var actualIssuers = validator.Validate(issuer, jwtSecurityToken, new TokenValidationParameters() { ValidIssuers = new[] { issuer } });

            IdentityComparer.AreEqual(issuer, actualIssuers, context);
            TestUtilities.AssertFailIfErrors(context);
        }

        [Theory]
        [InlineData(ValidatorConstants.ClaimNameTid, false)]
        [InlineData(ValidatorConstants.TenantId, false)]
        [InlineData(ValidatorConstants.ClaimNameTid, true)]
        [InlineData(ValidatorConstants.TenantId, true)]
        public void Validate_IssuerMatchedInValidIssuers_ReturnsIssuer(string tidClaimType, bool useConfigurationProvider)
        {
            var context = new CompareContext();

            AadIssuerValidator validator = null;
            if (useConfigurationProvider == false)
                validator = new AadIssuerValidator(_httpClient, ValidatorConstants.AadIssuer);
            else
                validator = new AadIssuerValidator(_httpClient, ValidatorConstants.AadIssuer, x => null);

            var tidClaim = new Claim(tidClaimType, ValidatorConstants.TenantIdAsGuid);

            var issClaim = new Claim(ValidatorConstants.ClaimNameIss, ValidatorConstants.AadIssuer);
            var jwtSecurityToken = new JwtSecurityToken(issuer: ValidatorConstants.AadIssuer, claims: new[] { issClaim, tidClaim });

            var actualIssuers = validator.Validate(ValidatorConstants.AadIssuer, jwtSecurityToken, new TokenValidationParameters() { ValidIssuers = new[] { ValidatorConstants.AadIssuer } });
            IdentityComparer.AreEqual(ValidatorConstants.AadIssuer, actualIssuers, context);

            ValidationResult<ValidatedIssuer, IssuerValidationError> validationResult = ValidateIssuerSync(
                ValidatorConstants.AadIssuer,
                ValidatorConstants.AadIssuer,
                jwtSecurityToken,
                validator);

            Assert.True(validationResult.Succeeded);
            var actualIssuer = validator.Validate(ValidatorConstants.AadIssuer, jwtSecurityToken, new TokenValidationParameters() { ValidIssuer = ValidatorConstants.AadIssuer });

            IdentityComparer.AreEqual(ValidatorConstants.AadIssuer, validationResult.Result.Issuer, context);
            IdentityComparer.AreEqual(ValidatorConstants.AadIssuer, actualIssuer, context);
            TestUtilities.AssertFailIfErrors(context);
        }

        [Theory]
        [InlineData(ValidatorConstants.ClaimNameTid, false)]
        [InlineData(ValidatorConstants.TenantId, false)]
        [InlineData(ValidatorConstants.ClaimNameTid, true)]
        [InlineData(ValidatorConstants.TenantId, true)]
        public void Validate_IssuerNotInTokenValidationParameters_ReturnsIssuer(string tidClaimType, bool useConfigurationProvider)
        {
            var context = new CompareContext();
            AadIssuerValidator validator = null;
            if (useConfigurationProvider == false)
                validator = new AadIssuerValidator(_httpClient, ValidatorConstants.AadIssuer);
            else
                validator = new AadIssuerValidator(_httpClient, ValidatorConstants.AadIssuer, authority => new MockConfigurationManager<OpenIdConnectConfiguration>(new OpenIdConnectConfiguration() { Issuer = ValidatorConstants.AadIssuer }));

            var tidClaim = new Claim(tidClaimType, ValidatorConstants.TenantIdAsGuid);

            var issClaim = new Claim(ValidatorConstants.ClaimNameIss, ValidatorConstants.AadIssuer);
            var jwtSecurityToken = new JwtSecurityToken(issuer: ValidatorConstants.AadIssuer, claims: new[] { issClaim, tidClaim });

            var actualIssuer = validator.Validate(ValidatorConstants.AadIssuer, jwtSecurityToken, new TokenValidationParameters());

            IdentityComparer.AreEqual(ValidatorConstants.AadIssuer, actualIssuer, context);
            TestUtilities.AssertFailIfErrors(context);
        }

        [Theory]
        [InlineData(ValidatorConstants.ClaimNameTid, ValidatorConstants.AadIssuer, false)]
        [InlineData(ValidatorConstants.TenantId, ValidatorConstants.AadIssuer, false)]
        [InlineData(ValidatorConstants.ClaimNameTid, ValidatorConstants.V1Issuer, false)]
        [InlineData(ValidatorConstants.TenantId, ValidatorConstants.V1Issuer, false)]
        [InlineData(ValidatorConstants.ClaimNameTid, ValidatorConstants.AadIssuer, true)]
        [InlineData(ValidatorConstants.TenantId, ValidatorConstants.AadIssuer, true)]
        [InlineData(ValidatorConstants.ClaimNameTid, ValidatorConstants.V1Issuer, true)]
        [InlineData(ValidatorConstants.TenantId, ValidatorConstants.V1Issuer, true)]
        public void ValidateJsonWebToken_ReturnsIssuer(string tidClaimType, string issuer, bool useConfigurationProvider)
        {
            AadIssuerValidator validator = null;
            if (useConfigurationProvider == false)
                validator = new AadIssuerValidator(_httpClient, issuer);
            else
                validator = new AadIssuerValidator(_httpClient, issuer, authority => new MockConfigurationManager<OpenIdConnectConfiguration>(new OpenIdConnectConfiguration() { Issuer = issuer }));

            var context = new CompareContext();
            var tidClaim = new Claim(tidClaimType, ValidatorConstants.TenantIdAsGuid);

            var issClaim = new Claim(ValidatorConstants.ClaimNameIss, issuer);
            List<Claim> claims = new List<Claim>();
            claims.Add(tidClaim);
            claims.Add(issClaim);

            var jsonWebToken = new JsonWebToken(Default.Jwt(Default.SecurityTokenDescriptor(Default.SymmetricSigningCredentials, claims)));
            var actualIssuer = validator.Validate(issuer, jsonWebToken, new TokenValidationParameters());
            ValidationResult<ValidatedIssuer, IssuerValidationError> validationResult = ValidateIssuerSync(
                issuer,
                jsonWebToken,
                validator);

            Assert.True(validationResult.Succeeded);
            IdentityComparer.AreEqual(issuer, validationResult.Result.Issuer, context);
            IdentityComparer.AreEqual(issuer, actualIssuer, context);
            TestUtilities.AssertFailIfErrors(context);
        }

        [Theory]
        [InlineData(ValidatorConstants.ClaimNameTid, false)]
        [InlineData(ValidatorConstants.TenantId, false)]
        [InlineData(ValidatorConstants.ClaimNameTid, true)]
        [InlineData(ValidatorConstants.TenantId, true)]
        public void Validate_V1IssuerNotInTokenValidationParameters_ReturnsV1Issuer(string tidClaimType, bool useConfigurationProvider)
        {
            AadIssuerValidator validator = null;
            if (useConfigurationProvider == false)
                validator = new AadIssuerValidator(_httpClient, ValidatorConstants.V1Issuer);
            else
                validator = new AadIssuerValidator(_httpClient, ValidatorConstants.V1Issuer, authority => new MockConfigurationManager<OpenIdConnectConfiguration>(new OpenIdConnectConfiguration() { Issuer = ValidatorConstants.V1Issuer }));

            var context = new CompareContext();
            var tidClaim = new Claim(tidClaimType, ValidatorConstants.TenantIdAsGuid);

            var issClaim = new Claim(ValidatorConstants.ClaimNameIss, ValidatorConstants.V1Issuer);
            var jwtSecurityToken = new JwtSecurityToken(issuer: ValidatorConstants.V1Issuer, claims: new[] { issClaim, tidClaim });

            var actualIssuer = validator.Validate(ValidatorConstants.V1Issuer, jwtSecurityToken, new TokenValidationParameters());
            ValidationResult<ValidatedIssuer, IssuerValidationError> validationResult = ValidateIssuerSync(
                ValidatorConstants.V1Issuer,
                jwtSecurityToken,
                validator);

            Assert.True(validationResult.Succeeded);
            IdentityComparer.AreEqual(ValidatorConstants.V1Issuer, validationResult.Result.Issuer, context);
            IdentityComparer.AreEqual(ValidatorConstants.V1Issuer, actualIssuer, context);
            TestUtilities.AssertFailIfErrors(context);
        }

        [Fact]
        public void Validate_TenantIdInIssuerNotInToken_ReturnsIssuer()
        {
            var context = new CompareContext();
            var validator = new AadIssuerValidator(_httpClient, ValidatorConstants.AadIssuer);
            var issClaim = new Claim(ValidatorConstants.ClaimNameIss, ValidatorConstants.AadIssuer);
            var jwtSecurityToken = new JwtSecurityToken(issuer: ValidatorConstants.AadIssuer, claims: new[] { issClaim });

            var actualIssuer = validator.Validate(ValidatorConstants.AadIssuer, jwtSecurityToken, new TokenValidationParameters() { ValidIssuer = ValidatorConstants.AadIssuer });
            ValidationResult<ValidatedIssuer, IssuerValidationError> validationResult = ValidateIssuerSync(
               ValidatorConstants.AadIssuer,
               ValidatorConstants.AadIssuer,
               jwtSecurityToken,
               validator);

            Assert.True(validationResult.Succeeded);
            IdentityComparer.AreEqual(ValidatorConstants.AadIssuer, validationResult.Result.Issuer, context);
            IdentityComparer.AreEqual(ValidatorConstants.AadIssuer, actualIssuer, context);
            TestUtilities.AssertFailIfErrors(context);
        }

        [Fact]
        public void Validate_TidClaimInToken_ReturnsIssuer()
        {
            var context = new CompareContext();
            var validator = new AadIssuerValidator(_httpClient, ValidatorConstants.AadIssuer);
            var tidClaim = new Claim(ValidatorConstants.ClaimNameTid, ValidatorConstants.TenantIdAsGuid);
            var issClaim = new Claim(ValidatorConstants.ClaimNameIss, ValidatorConstants.AadIssuer);
            var jwtSecurityToken = new JwtSecurityToken(issuer: ValidatorConstants.AadIssuer, claims: new[] { issClaim, tidClaim });
            var jsonWebToken = new JsonWebToken($"{{}}", $"{{\"{ValidatorConstants.ClaimNameIss}\":\"{ValidatorConstants.AadIssuer}\",\"{ValidatorConstants.ClaimNameTid}\":\"{ValidatorConstants.TenantIdAsGuid}\"}}");

            var actualIssuer = validator.Validate(ValidatorConstants.AadIssuer, jwtSecurityToken, new TokenValidationParameters() { ValidIssuer = ValidatorConstants.AadIssuer });
            ValidationResult<ValidatedIssuer, IssuerValidationError> validationResult = ValidateIssuerSync(
                ValidatorConstants.AadIssuer,
                ValidatorConstants.AadIssuer,
                jwtSecurityToken,
                validator);

            Assert.True(validationResult.Succeeded);
            IdentityComparer.AreEqual(ValidatorConstants.AadIssuer, validationResult.Result.Issuer, context);
            IdentityComparer.AreEqual(ValidatorConstants.AadIssuer, actualIssuer, context);

            IdentityComparer.AreEqual(ValidatorConstants.AadIssuer, actualIssuer, context);

            actualIssuer = validator.Validate(ValidatorConstants.AadIssuer, jsonWebToken, new TokenValidationParameters() { ValidIssuer = ValidatorConstants.AadIssuer });
            validationResult = ValidateIssuerSync(
                ValidatorConstants.AadIssuer,
                ValidatorConstants.AadIssuer,
                jsonWebToken,
                validator);

            Assert.True(validationResult.Succeeded);
            IdentityComparer.AreEqual(ValidatorConstants.AadIssuer, validationResult.Result.Issuer, context);
            IdentityComparer.AreEqual(ValidatorConstants.AadIssuer, actualIssuer, context);
            TestUtilities.AssertFailIfErrors(context);
        }

        // Regression test for https://github.com/Azure-Samples/active-directory-dotnet-native-aspnetcore-v2/issues/68
        // Similar to Validate_NotMatchedToMultipleIssuers_ThrowsException but uses B2C values
        [Fact]
        public void Validate_InvalidIssuerToValidate_ThrowsException()
        {
            var context = new CompareContext();
            string invalidIssuerToValidate = $"https://badissuer/{ValidatorConstants.TenantIdAsGuid}/v2.0";
            AadIssuerValidator validator = new AadIssuerValidator(_httpClient, invalidIssuerToValidate);
            Claim issClaim = new Claim(ValidatorConstants.ClaimNameIss, ValidatorConstants.AadIssuer);
            Claim tidClaim = new Claim(ValidatorConstants.ClaimNameTid, ValidatorConstants.TenantIdAsGuid);
            JwtSecurityToken jwtSecurityToken = new JwtSecurityToken(issuer: ValidatorConstants.AadIssuer, claims: new[] { issClaim, tidClaim });
            var expectedErrorMessage = string.Format(
                    CultureInfo.InvariantCulture,
                    LogMessages.IDX40001,
                    invalidIssuerToValidate);

            var exception = Assert.Throws<SecurityTokenInvalidIssuerException>(() =>
                validator.Validate(invalidIssuerToValidate, jwtSecurityToken, new TokenValidationParameters() { ValidIssuers = new[] { ValidatorConstants.AadIssuer } }));

            ValidationResult<ValidatedIssuer, IssuerValidationError> validationResult = ValidateIssuerSync(
                invalidIssuerToValidate,
                ValidatorConstants.AadIssuer,
                jwtSecurityToken,
                validator);

            Assert.False(validationResult.Succeeded);
            IdentityComparer.AreEqual(expectedErrorMessage, validationResult.Error.MessageDetail.Message, context);

            IdentityComparer.AreEqual(expectedErrorMessage, exception.Message, context);
            TestUtilities.AssertFailIfErrors(context);
        }

        [Fact]
        public void Validate_FromB2CAuthority_WithNoTidClaim_ValidateSuccessfully()
        {
            var context = new CompareContext();
            Claim issClaim = new Claim(ValidatorConstants.ClaimNameIss, ValidatorConstants.B2CIssuer);
            Claim tfpClaim = new Claim(ValidatorConstants.ClaimNameTfp, ValidatorConstants.B2CSignUpSignInUserFlow);
            JwtSecurityToken jwtSecurityToken = new JwtSecurityToken(issuer: ValidatorConstants.B2CIssuer, claims: new[] { issClaim, tfpClaim });

            AadIssuerValidator validator = CreateIssuerValidator(ValidatorConstants.B2CAuthorityWithV2);

            string issuer = validator.Validate(
                ValidatorConstants.B2CIssuer,
                jwtSecurityToken,
                new TokenValidationParameters()
                {
                    ValidIssuers = new[] { ValidatorConstants.B2CIssuer },
                });

            ValidationResult<ValidatedIssuer, IssuerValidationError> validationResult = ValidateIssuerSync(
                ValidatorConstants.B2CIssuer,
                ValidatorConstants.B2CIssuer,
                jwtSecurityToken,
                validator);

            Assert.True(validationResult.Succeeded);
            IdentityComparer.AreEqual(ValidatorConstants.B2CIssuer, validationResult.Result.Issuer, context);
            IdentityComparer.AreEqual(ValidatorConstants.B2CIssuer, issuer, context);

            IdentityComparer.AreEqual(ValidatorConstants.B2CAuthority, validator.AadAuthorityV1, context);
            IdentityComparer.AreEqual(ValidatorConstants.B2CAuthorityWithV2, validator.AadAuthorityV2, context);
            IdentityComparer.AreEqual(ProtocolVersion.V2, validator.AadAuthorityVersion, context);
            TestUtilities.AssertFailIfErrors(context);
        }

        [Fact]
        public void Validate_FromB2CAuthority_WithTokenValidateParametersValidIssuersUnspecified_ValidateSuccessfully()
        {
            var context = new CompareContext();
            var issClaim = new Claim(ValidatorConstants.ClaimNameIss, ValidatorConstants.B2CIssuer);
            var tfpClaim = new Claim(ValidatorConstants.ClaimNameTfp, ValidatorConstants.B2CSignUpSignInUserFlow);
            var jwtSecurityToken = new JwtSecurityToken(issuer: ValidatorConstants.B2CIssuer, claims: new[] { issClaim, tfpClaim });
            BaseConfigurationManager configurationManager = new MockConfigurationManager<OpenIdConnectConfiguration>(new OpenIdConnectConfiguration()
            {
                Issuer = ValidatorConstants.B2CIssuer
            });

            var validator = new AadIssuerValidator(null, ValidatorConstants.B2CAuthority);

            var tokenValidationParams = new TokenValidationParameters()
            {
                ConfigurationManager = configurationManager
            };

            string issuer = validator.Validate(
                ValidatorConstants.B2CIssuer,
                jwtSecurityToken,
                tokenValidationParams);

            ValidationResult<ValidatedIssuer, IssuerValidationError> validationResult = ValidateIssuerSync(
                ValidatorConstants.B2CIssuer,
                configurationManager,
                jwtSecurityToken,
                validator);

            Assert.True(validationResult.Succeeded);
            IdentityComparer.AreEqual(ValidatorConstants.B2CIssuer, validationResult.Result.Issuer, context);
            IdentityComparer.AreEqual(ValidatorConstants.B2CIssuer, issuer, context);

            TestUtilities.AssertFailIfErrors(context);
        }

        [Fact]
        public void Validate_FromB2CAuthority_WithTidClaim_ValidateSuccessfully()
        {
            var context = new CompareContext();
            Claim issClaim = new Claim(ValidatorConstants.ClaimNameIss, ValidatorConstants.B2CIssuer);
            Claim tfpClaim = new Claim(ValidatorConstants.ClaimNameTfp, ValidatorConstants.B2CSignUpSignInUserFlow);
            Claim tidClaim = new Claim(ValidatorConstants.ClaimNameTid, ValidatorConstants.B2CTenantAsGuid);
            JwtSecurityToken jwtSecurityToken = new JwtSecurityToken(issuer: ValidatorConstants.B2CIssuer, claims: new[] { issClaim, tfpClaim, tidClaim });

            AadIssuerValidator validator = CreateIssuerValidator(ValidatorConstants.B2CAuthorityWithV2);

            string issuer = validator.Validate(
                ValidatorConstants.B2CIssuer,
                jwtSecurityToken,
                new TokenValidationParameters()
                {
                    ValidIssuers = new[] { ValidatorConstants.B2CIssuer },
                });

            ValidationResult<ValidatedIssuer, IssuerValidationError> validationResult = ValidateIssuerSync(
                ValidatorConstants.B2CIssuer,
                ValidatorConstants.B2CIssuer,
                jwtSecurityToken,
                validator);

            Assert.True(validationResult.Succeeded);
            IdentityComparer.AreEqual(ValidatorConstants.B2CIssuer, validationResult.Result.Issuer, context);
            IdentityComparer.AreEqual(ValidatorConstants.B2CIssuer, issuer, context);

            IdentityComparer.AreEqual(ValidatorConstants.B2CAuthority, validator.AadAuthorityV1, context);
            IdentityComparer.AreEqual(ValidatorConstants.B2CAuthorityWithV2, validator.AadAuthorityV2, context);
            IdentityComparer.AreEqual(ProtocolVersion.V2, validator.AadAuthorityVersion, context);
            TestUtilities.AssertFailIfErrors(context);
        }

        [Fact]
        public void Validate_FromB2CAuthority_InvalidIssuer_Fails()
        {
            var context = new CompareContext();
            Claim issClaim = new Claim(ValidatorConstants.ClaimNameIss, ValidatorConstants.B2CIssuer2);
            Claim tfpClaim = new Claim(ValidatorConstants.ClaimNameTfp, ValidatorConstants.B2CSignUpSignInUserFlow);
            JwtSecurityToken jwtSecurityToken = new JwtSecurityToken(issuer: ValidatorConstants.B2CIssuer2, claims: new[] { issClaim, tfpClaim });

            AadIssuerValidator validator = CreateIssuerValidator(ValidatorConstants.B2CAuthorityWithV2);

            var exception = Assert.Throws<SecurityTokenInvalidIssuerException>(() =>
                validator.Validate(
                    ValidatorConstants.B2CIssuer2,
                    jwtSecurityToken,
                    new TokenValidationParameters()
                    {
                        ValidIssuers = new[] { ValidatorConstants.B2CIssuer },
                    }));

            ValidationResult<ValidatedIssuer, IssuerValidationError> validationResult = ValidateIssuerSync(
                ValidatorConstants.B2CIssuer2,
                ValidatorConstants.B2CIssuer,
                jwtSecurityToken,
                validator);

            string expectedMessage = string.Format(LogMessages.IDX40001, ValidatorConstants.B2CIssuer2);
            IdentityComparer.AreEqual(expectedMessage, validationResult.Error.MessageDetail.Message, context);
            IdentityComparer.AreEqual(expectedMessage, exception.Message, context);
            TestUtilities.AssertFailIfErrors(context);
        }

        [Fact]
        public void Validate_FromB2CAuthority_InvalidIssuerTid_Fails()
        {
            var context = new CompareContext();
            string issuerWithInvalidTid = ValidatorConstants.B2CInstance + "/" + ValidatorConstants.TenantIdAsGuid + "/v2.0";
            Claim issClaim = new Claim(ValidatorConstants.ClaimNameIss, issuerWithInvalidTid);
            Claim tfpClaim = new Claim(ValidatorConstants.ClaimNameTfp, ValidatorConstants.B2CSignUpSignInUserFlow);
            JwtSecurityToken jwtSecurityToken = new JwtSecurityToken(issuer: issuerWithInvalidTid, claims: new[] { issClaim, tfpClaim });

            AadIssuerValidator validator = CreateIssuerValidator(ValidatorConstants.B2CAuthorityWithV2);

            var exception = Assert.Throws<SecurityTokenInvalidIssuerException>(() =>
                validator.Validate(
                    issuerWithInvalidTid,
                    jwtSecurityToken,
                    new TokenValidationParameters()
                    {
                        ValidIssuers = new[] { ValidatorConstants.B2CIssuer },
                    }));

            ValidationResult<ValidatedIssuer, IssuerValidationError> validationResult = ValidateIssuerSync(
                    issuerWithInvalidTid,
                    ValidatorConstants.B2CIssuer,
                    jwtSecurityToken,
                    validator);

            string expectedMessage = string.Format(LogMessages.IDX40001, issuerWithInvalidTid);
            IdentityComparer.AreEqual(expectedMessage, validationResult.Error.MessageDetail.Message, context);
            IdentityComparer.AreEqual(expectedMessage, exception.Message, context);
            TestUtilities.AssertFailIfErrors(context);
        }

        [Fact]
        public void Validate_FromCustomB2CAuthority_ValidateSuccessfully()
        {
            var context = new CompareContext();
            Claim issClaim = new Claim(ValidatorConstants.ClaimNameIss, ValidatorConstants.B2CCustomDomainIssuer);
            Claim tfpClaim = new Claim(ValidatorConstants.ClaimNameTfp, ValidatorConstants.B2CCustomDomainUserFlow);
            JwtSecurityToken jwtSecurityToken = new JwtSecurityToken(issuer: ValidatorConstants.B2CCustomDomainIssuer, claims: new[] { issClaim, tfpClaim });

            AadIssuerValidator validator = CreateIssuerValidator(ValidatorConstants.B2CCustomDomainAuthorityWithV2);

            string issuer = validator.Validate(
                ValidatorConstants.B2CCustomDomainIssuer,
                jwtSecurityToken,
                new TokenValidationParameters()
                {
                    ValidIssuers = new[] { ValidatorConstants.B2CCustomDomainIssuer },
                });

            ValidationResult<ValidatedIssuer, IssuerValidationError> validationResult = ValidateIssuerSync(
                ValidatorConstants.B2CCustomDomainIssuer,
                ValidatorConstants.B2CCustomDomainIssuer,
                jwtSecurityToken,
                validator);

            Assert.True(validationResult.Succeeded);
            IdentityComparer.AreEqual(ValidatorConstants.B2CCustomDomainIssuer, validationResult.Result.Issuer, context);
            IdentityComparer.AreEqual(ValidatorConstants.B2CCustomDomainIssuer, issuer, context);

            IdentityComparer.AreEqual(ValidatorConstants.B2CCustomDomainAuthority, validator.AadAuthorityV1, context);
            IdentityComparer.AreEqual(ValidatorConstants.B2CCustomDomainAuthorityWithV2, validator.AadAuthorityV2, context);
            IdentityComparer.AreEqual(ProtocolVersion.V2, validator.AadAuthorityVersion, context);
            TestUtilities.AssertFailIfErrors(context);
        }

        [Fact]
        public void Validate_FromB2CAuthority_WithTfpIssuer_ThrowsException()
        {
            var context = new CompareContext();
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

            ValidationResult<ValidatedIssuer, IssuerValidationError> validationResult = ValidateIssuerSync(
                ValidatorConstants.B2CIssuerTfp,
                ValidatorConstants.B2CIssuerTfp,
                jwtSecurityToken,
                validator);

            Assert.False(validationResult.Succeeded);
            IdentityComparer.AreEqual(LogMessages.IDX40002, validationResult.Error.MessageDetail.Message, context);
            IdentityComparer.AreEqual(LogMessages.IDX40002, exception.Message, context);
            TestUtilities.AssertFailIfErrors(context);
        }

#if NET5_0_OR_GREATER
        [Theory]
        [InlineData(ProtocolVersion.V1, ProtocolVersion.V1)]
        [InlineData(ProtocolVersion.V1, ProtocolVersion.V11)]
        [InlineData(ProtocolVersion.V1, ProtocolVersion.V2)]
        [InlineData(ProtocolVersion.V11, ProtocolVersion.V1)]
        [InlineData(ProtocolVersion.V11, ProtocolVersion.V11)]
        [InlineData(ProtocolVersion.V11, ProtocolVersion.V2)]
        [InlineData(ProtocolVersion.V2, ProtocolVersion.V1)]
        [InlineData(ProtocolVersion.V2, ProtocolVersion.V11)]
        [InlineData(ProtocolVersion.V2, ProtocolVersion.V2)]
        public void Validate_WithAuthorityUsingConfigurationProvider(ProtocolVersion authorityVersion, ProtocolVersion tokenVersion)
        {
            var configurationManagerProvider = (string authority) =>
            {
                var configManagerMap = new Dictionary<string, BaseConfigurationManager>
                {
                    {
                        ValidatorConstants.AuthorityV1,
                        new MockConfigurationManager<OpenIdConnectConfiguration>(
                           new OpenIdConnectConfiguration()
                           {
                               Issuer = ValidatorConstants.AadIssuerV1CommonAuthority
                           })
                    },
                    {
                        ValidatorConstants.AuthorityCommonTenantWithV2,
                        new MockConfigurationManager<OpenIdConnectConfiguration>(
                           new OpenIdConnectConfiguration()
                           {
                               Issuer = ValidatorConstants.AadIssuerV2CommonAuthority
                           })
                    },
                    {
                        ValidatorConstants.AuthorityCommonTenantWithV11,
                        new MockConfigurationManager<OpenIdConnectConfiguration>(
                            new OpenIdConnectConfiguration()
                            {
                                Issuer = ValidatorConstants.AadIssuerV11CommonAuthority
                            })
                    }
                };

                return configManagerMap[authority];
            };

            var tokenIssuerProvider = (ProtocolVersion version) =>
            {
                if (version == ProtocolVersion.V11)
                    return ValidatorConstants.AadIssuerV11;

                if (version == ProtocolVersion.V2)
                    return ValidatorConstants.AadIssuer;

                return ValidatorConstants.V1Issuer;
            };

            var authorityUrlProvider = (ProtocolVersion version) =>
            {
                if (version == ProtocolVersion.V11)
                    return ValidatorConstants.AuthorityCommonTenantWithV11;

                if (version == ProtocolVersion.V2)
                    return ValidatorConstants.AuthorityCommonTenantWithV2;

                return ValidatorConstants.AuthorityV1;
            };

            var context = new CompareContext();
            var tidClaim = new Claim(ValidatorConstants.ClaimNameTid, ValidatorConstants.TenantIdAsGuid);

            var tokenIssuer = tokenIssuerProvider(tokenVersion);
            var issClaim = new Claim(ValidatorConstants.ClaimNameIss, tokenIssuer);
            var jwtSecurityToken = new JwtSecurityToken(issuer: tokenIssuer, claims: new[] { issClaim, tidClaim });

            var authority = authorityUrlProvider(authorityVersion);
            var aadIssuerValidator = AadIssuerValidator.GetAadIssuerValidator(authority, _httpClient, configurationManagerProvider);

            var actualIssuer = aadIssuerValidator.Validate(tokenIssuer, jwtSecurityToken, new TokenValidationParameters());
            ValidationResult<ValidatedIssuer, IssuerValidationError> validationResult = ValidateIssuerSync(
                tokenIssuer,
                jwtSecurityToken,
                aadIssuerValidator);

            Assert.True(validationResult.Succeeded);
            IdentityComparer.AreEqual(tokenIssuer, validationResult.Result.Issuer, context);
            IdentityComparer.AreEqual(tokenIssuer, actualIssuer, context);
            TestUtilities.AssertFailIfErrors(context);
        }

        [Theory]
        [InlineData(ProtocolVersion.V1, ProtocolVersion.V1)]
        [InlineData(ProtocolVersion.V1, ProtocolVersion.V11)]
        [InlineData(ProtocolVersion.V1, ProtocolVersion.V2)]
        [InlineData(ProtocolVersion.V11, ProtocolVersion.V1)]
        [InlineData(ProtocolVersion.V11, ProtocolVersion.V11)]
        [InlineData(ProtocolVersion.V11, ProtocolVersion.V2)]
        [InlineData(ProtocolVersion.V2, ProtocolVersion.V1)]
        [InlineData(ProtocolVersion.V2, ProtocolVersion.V11)]
        [InlineData(ProtocolVersion.V2, ProtocolVersion.V2)]
        public void Validate_UsesLKGWithoutConfigurationProvider(ProtocolVersion authorityVersion, ProtocolVersion tokenVersion)
        {
            var tokenIssuerProvider = (ProtocolVersion version) =>
            {
                if (version == ProtocolVersion.V11)
                    return ValidatorConstants.AadIssuerV11;

                if (version == ProtocolVersion.V2)
                    return ValidatorConstants.AadIssuer;

                return ValidatorConstants.V1Issuer;
            };

            var authorityUrlProvider = (ProtocolVersion version) =>
            {
                if (version == ProtocolVersion.V11)
                    return ValidatorConstants.AuthorityCommonTenantWithV11;

                if (version == ProtocolVersion.V2)
                    return ValidatorConstants.AuthorityCommonTenantWithV2;

                return ValidatorConstants.AuthorityV1;
            };

            var goodAuthorityIssuer = (ProtocolVersion version) =>
            {
                if (version == ProtocolVersion.V11)
                    return ValidatorConstants.AadIssuerV11CommonAuthority;

                if (version == ProtocolVersion.V2)
                    return ValidatorConstants.AadIssuerV2CommonAuthority;

                return ValidatorConstants.AadIssuerV1CommonAuthority;
            };

            var configurationManagerSetter = (AadIssuerValidator validator, bool isRefresh = false) =>
            {
                if (!isRefresh)
                {
                    validator.ConfigurationManagerV1 = new MockConfigurationManager<OpenIdConnectConfiguration>(
                        new OpenIdConnectConfiguration
                        {
                            Issuer = goodAuthorityIssuer(ProtocolVersion.V1)
                        });
                    validator.ConfigurationManagerV11 = new MockConfigurationManager<OpenIdConnectConfiguration>(
                        new OpenIdConnectConfiguration
                        {
                            Issuer = goodAuthorityIssuer(ProtocolVersion.V11)
                        });
                    validator.ConfigurationManagerV2 = new MockConfigurationManager<OpenIdConnectConfiguration>(
                        new OpenIdConnectConfiguration
                        {
                            Issuer = goodAuthorityIssuer(ProtocolVersion.V2)
                        });
                }
                else
                {
                    var refreshedConfig = new OpenIdConnectConfiguration
                    {
                        Issuer = "hxxp://brokenissuer/{tenantid}"
                    };

                    ((MockConfigurationManager<OpenIdConnectConfiguration>)validator.ConfigurationManagerV11).RefreshedConfiguration = refreshedConfig;
                    ((MockConfigurationManager<OpenIdConnectConfiguration>)validator.ConfigurationManagerV2).RefreshedConfiguration = refreshedConfig;
                    ((MockConfigurationManager<OpenIdConnectConfiguration>)validator.ConfigurationManagerV1).RefreshedConfiguration = refreshedConfig;
                    validator.ConfigurationManagerV11.RequestRefresh();
                    validator.ConfigurationManagerV2.RequestRefresh();
                    validator.ConfigurationManagerV1.RequestRefresh();
                }
            };

            var context = new CompareContext();
            var tidClaim = new Claim(ValidatorConstants.ClaimNameTid, ValidatorConstants.TenantIdAsGuid);

            var issuer = tokenIssuerProvider(tokenVersion);
            var issClaim = new Claim(ValidatorConstants.ClaimNameIss, issuer);
            var jwtSecurityToken = new JwtSecurityToken(issuer: issuer, claims: new[] { issClaim, tidClaim });

            var authority = authorityUrlProvider(authorityVersion);
            var aadIssuerValidator = AadIssuerValidator.GetAadIssuerValidator(authority, _httpClient);

            // set config to a mock and assert on LKG being null
            configurationManagerSetter(aadIssuerValidator);

            // set LKG
            var actualIssuer = aadIssuerValidator.Validate(issuer, jwtSecurityToken, new TokenValidationParameters());
            ValidationResult<ValidatedIssuer, IssuerValidationError> validationResult = ValidateIssuerSync(
                          issuer,
                          jwtSecurityToken,
                          aadIssuerValidator);

            Assert.True(validationResult.Succeeded);
            IdentityComparer.AreEqual(issuer, validationResult.Result.Issuer, context);
            IdentityComparer.AreEqual(issuer, actualIssuer, context);
            TestUtilities.AssertFailIfErrors(context);

            // replace config with broken issuer and validate with LKG
            configurationManagerSetter(aadIssuerValidator, true);

            actualIssuer = aadIssuerValidator.Validate(issuer, jwtSecurityToken, new TokenValidationParameters { ValidateWithLKG = true });
            validationResult = ValidateIssuerSync(
                          issuer,
                          jwtSecurityToken,
                          aadIssuerValidator,
                          true);

            Assert.True(validationResult.Succeeded);
            IdentityComparer.AreEqual(issuer, validationResult.Result.Issuer, context);
            IdentityComparer.AreEqual(issuer, actualIssuer, context);
            TestUtilities.AssertFailIfErrors(context);
        }

        [Theory]
        [InlineData(ProtocolVersion.V1, ProtocolVersion.V1)]
        [InlineData(ProtocolVersion.V1, ProtocolVersion.V11)]
        [InlineData(ProtocolVersion.V1, ProtocolVersion.V2)]
        [InlineData(ProtocolVersion.V11, ProtocolVersion.V1)]
        [InlineData(ProtocolVersion.V11, ProtocolVersion.V11)]
        [InlineData(ProtocolVersion.V11, ProtocolVersion.V2)]
        [InlineData(ProtocolVersion.V2, ProtocolVersion.V1)]
        [InlineData(ProtocolVersion.V2, ProtocolVersion.V11)]
        [InlineData(ProtocolVersion.V2, ProtocolVersion.V2)]
        public void Validate_CanFetchMetadataWithoutConfigurationProvider(ProtocolVersion authorityVersion, ProtocolVersion tokenVersion)
        {
            var tokenIssuerProvider = (ProtocolVersion version) =>
            {
                if (version == ProtocolVersion.V11)
                    return ValidatorConstants.AadIssuerV11PPE;

                if (version == ProtocolVersion.V2)
                    return ValidatorConstants.AadIssuerPPE;

                return ValidatorConstants.V1IssuerPPE;
            };

            var authorityUrlProvider = (ProtocolVersion version) =>
            {
                if (version == ProtocolVersion.V11)
                    return ValidatorConstants.AuthorityCommonTenantWithV11PPE;

                if (version == ProtocolVersion.V2)
                    return ValidatorConstants.AuthorityCommonTenantWithV2PPE;

                return ValidatorConstants.AuthorityV1PPE;
            };

            var context = new CompareContext();
            var tidClaim = new Claim(ValidatorConstants.ClaimNameTid, ValidatorConstants.TenantIdAsGuid);

            var issuer = tokenIssuerProvider(tokenVersion);
            var issClaim = new Claim(ValidatorConstants.ClaimNameIss, issuer);
            var jwtSecurityToken = new JwtSecurityToken(issuer: issuer, claims: new[] { issClaim, tidClaim });

            var authority = authorityUrlProvider(authorityVersion);

            // Serve OpenID Connect metadata and a JWKS from in-memory fixtures through a mock HTTP handler
            // instead of calling the live pre-production metadata endpoint, which is not reachable from CI
            // runners. Every layer below the HTTP transport stays real, so the retriever, serializer, and
            // key-set parsing run exactly as they would against the live document.
            // The metadata issuer is the same {tenantid} template the live endpoint returns, so the validator
            // still matches the token issuer through its normal tenant-substitution logic. Issuer validation
            // only reads Issuer and JwksUri, so a minimal metadata document is sufficient.
            string issuerTemplate = issuer.Replace(ValidatorConstants.TenantIdAsGuid, AadIssuerValidator.TenantIdTemplate);
            string metadataJson = OpenIdConnectConfiguration.Write(
                new OpenIdConnectConfiguration { Issuer = issuerTemplate, JwksUri = PlaceholderJwksUri });
            string jwksJson = KeyingMaterial.AADJWKS;

            var handler = new DelegateHttpMessageHandler((request, ct) =>
            {
                string url = request.RequestUri.AbsoluteUri;

                if (url.EndsWith(OpenIdConfigurationPath, StringComparison.OrdinalIgnoreCase))
                    return Task.FromResult(HttpResponseMessageUtils.CreateHttpResponseMessage(metadataJson));

                if (url.IndexOf(DiscoveryPathMarker, StringComparison.OrdinalIgnoreCase) >= 0 ||
                    url.EndsWith(KeysPathMarker, StringComparison.OrdinalIgnoreCase))
                    return Task.FromResult(HttpResponseMessageUtils.CreateHttpResponseMessage(jwksJson));

                throw new InvalidOperationException(UnexpectedUrlMessagePrefix + url);
            });

            using var mockHttpClient = new HttpClient(handler);
            var validator = AadIssuerValidator.GetAadIssuerValidator(authority, mockHttpClient);

            ValidationResult<ValidatedIssuer, IssuerValidationError> validationResult = ValidateIssuerSync(issuer, jwtSecurityToken, validator);
            var actualIssuer = validator.Validate(issuer, jwtSecurityToken, new TokenValidationParameters());

            Assert.True(validationResult.Succeeded);
            IdentityComparer.AreEqual(issuer, validationResult.Result.Issuer, context);
            IdentityComparer.AreEqual(issuer, actualIssuer, context);
            TestUtilities.AssertFailIfErrors(context);
        }
#endif

        // Negative coverage for the metadata-fetch-failure path. When the mock handler rejects the discovery
        // request (for example, a 403), the validator surfaces IDX40001. This deterministically exercises
        // HttpDocumentRetriever's failure path and AadIssuerValidator's catch that maps the fetch failure to
        // IDX40001, which previously ran only when the live endpoint happened to fail.
        [Fact]
        public void Validate_WithoutConfigurationProvider_MetadataFetchForbidden_ThrowsIDX40001()
        {
            var context = new CompareContext();
            var issuer = ValidatorConstants.AadIssuerPPE;
            var authority = ValidatorConstants.AuthorityCommonTenantWithV2PPE;

            // Build a token whose issuer and tenant id match the authority, so validation gets past the
            // issuer/tenant checks and reaches the on-demand metadata fetch.
            var issClaim = new Claim(ValidatorConstants.ClaimNameIss, issuer);
            var tidClaim = new Claim(ValidatorConstants.ClaimNameTid, ValidatorConstants.TenantIdAsGuid);
            var jwtSecurityToken = new JwtSecurityToken(issuer: issuer, claims: new[] { issClaim, tidClaim });

            // Reject the OpenID Connect discovery request with 403 to simulate an unreachable metadata
            // endpoint. Validation fails before the JWKS is requested, so any other URL is unexpected here.
            var handler = new DelegateHttpMessageHandler((request, ct) =>
            {
                string url = request.RequestUri.AbsoluteUri;

                if (url.EndsWith(OpenIdConfigurationPath, StringComparison.OrdinalIgnoreCase))
                    return Task.FromResult(HttpResponseMessageUtils.CreateHttpResponseMessage(string.Empty, HttpStatusCode.Forbidden));

                throw new InvalidOperationException(UnexpectedUrlMessagePrefix + url);
            });

            using var mockHttpClient = new HttpClient(handler);
            var validator = AadIssuerValidator.GetAadIssuerValidator(authority, mockHttpClient);

            // The failed metadata fetch leaves the validator without issuer metadata, so it reports IDX40001.
            var expectedErrorMessage = string.Format(
                CultureInfo.InvariantCulture,
                LogMessages.IDX40001,
                issuer);

            // Validate surfaces the failure as SecurityTokenInvalidIssuerException carrying the IDX40001 message.
            var exception = Assert.Throws<SecurityTokenInvalidIssuerException>(() =>
                validator.Validate(issuer, jwtSecurityToken, new TokenValidationParameters()));

            IdentityComparer.AreEqual(expectedErrorMessage, exception.Message, context);
            TestUtilities.AssertFailIfErrors(context);
        }

        [Fact]
        public void Validate_UsesLKGWithConfigurationProvider()
        {
            var v1Configuration = new OpenIdConnectConfiguration
            {
                Issuer = ValidatorConstants.AadIssuerV1CommonAuthority
            };

            var v1ConfigurationRefreshed = new OpenIdConnectConfiguration
            {
                Issuer = "hxxp://brokenissuer/{tenantid}"
            };

            var v2Configuration = new OpenIdConnectConfiguration
            {
                Issuer = ValidatorConstants.AadIssuerV2CommonAuthority
            };

            var v2ConfigurationRefreshed = new OpenIdConnectConfiguration
            {
                Issuer = "hxxp://brokenissuer/{tenantid}"
            };

            var v1ConfigurationManager = new MockConfigurationManager<OpenIdConnectConfiguration>(v1Configuration);
            var v2ConfigurationManager = new MockConfigurationManager<OpenIdConnectConfiguration>(v2Configuration);

            var configurationManagerProvider = (string authority) =>
            {
                var configManagerMap = new Dictionary<string, BaseConfigurationManager>
                {
                    {
                        ValidatorConstants.AuthorityV1,
                        v1ConfigurationManager
                    },
                    {
                        ValidatorConstants.AuthorityCommonTenantWithV2,
                        v2ConfigurationManager
                    }
                };

                return configManagerMap[authority];
            };

            var context = new CompareContext();
            var tidClaim = new Claim(ValidatorConstants.ClaimNameTid, ValidatorConstants.TenantIdAsGuid);

            var v2TokenIssuer = ValidatorConstants.AadIssuer;
            var issClaim = new Claim(ValidatorConstants.ClaimNameIss, v2TokenIssuer);
            var jwtSecurityToken = new JwtSecurityToken(issuer: v2TokenIssuer, claims: new[] { issClaim, tidClaim });

            var v2Authority = ValidatorConstants.AuthorityCommonTenantWithV2;
            var v1Authority = ValidatorConstants.AuthorityCommonTenant;
            var aadIssuerValidator = AadIssuerValidator.GetAadIssuerValidator(v2Authority, _httpClient, configurationManagerProvider);
            var v1AadIssuerValidator = AadIssuerValidator.GetAadIssuerValidator(v1Authority, _httpClient, configurationManagerProvider);

            // set LKG
            var actualIssuer = aadIssuerValidator.Validate(v2TokenIssuer, jwtSecurityToken, new TokenValidationParameters());
            ValidationResult<ValidatedIssuer, IssuerValidationError> validationResult = ValidateIssuerSync(
               v2TokenIssuer,
               jwtSecurityToken,
               aadIssuerValidator);

            Assert.True(validationResult.Succeeded);
            IdentityComparer.AreEqual(v2TokenIssuer, validationResult.Result.Issuer, context);
            IdentityComparer.AreEqual(v2TokenIssuer, actualIssuer, context);
            TestUtilities.AssertFailIfErrors(context);

            // refresh config to a one with a broken issuer and validate with LKG
            v2ConfigurationManager.RefreshedConfiguration = v2ConfigurationRefreshed;
            v2ConfigurationManager.RequestRefresh();

            actualIssuer = aadIssuerValidator.Validate(v2TokenIssuer, jwtSecurityToken, new TokenValidationParameters { ValidateWithLKG = true });
            validationResult = ValidateIssuerSync(
               v2TokenIssuer,
               jwtSecurityToken,
               aadIssuerValidator,
               true);

            Assert.True(validationResult.Succeeded);
            IdentityComparer.AreEqual(v2TokenIssuer, validationResult.Result.Issuer, context);
            IdentityComparer.AreEqual(v2TokenIssuer, actualIssuer, context);
            TestUtilities.AssertFailIfErrors(context);

            var v1TokenIssuer = ValidatorConstants.V1Issuer;
            issClaim = new Claim(ValidatorConstants.ClaimNameIss, v1TokenIssuer);
            var v1JwtSecurityToken = new JwtSecurityToken(issuer: v1TokenIssuer, claims: new[] { issClaim, tidClaim });

            // before testing v1 LKG setup v1 LKG for v2 manager for cross version validation
            _ = aadIssuerValidator.Validate(v1TokenIssuer, v1JwtSecurityToken, new TokenValidationParameters());
            _ = ValidateIssuerSync(
               v1TokenIssuer,
               v1JwtSecurityToken,
               aadIssuerValidator);

            // V1 token and authority behaves like v2 token and authority
            actualIssuer = v1AadIssuerValidator.Validate(v1TokenIssuer, v1JwtSecurityToken, new TokenValidationParameters());
            validationResult = ValidateIssuerSync(
               v1TokenIssuer,
               v1JwtSecurityToken,
               aadIssuerValidator);

            IdentityComparer.AreEqual(validationResult.Result.Issuer, v1TokenIssuer, context);
            IdentityComparer.AreEqual(v1TokenIssuer, actualIssuer, context);
            IdentityComparer.AreEqual(null, v1ConfigurationManager.LastKnownGoodConfiguration, context);
            TestUtilities.AssertFailIfErrors(context);

            //      refresh config to a broken one and validate with LKG
            v1ConfigurationManager.RefreshedConfiguration = v1ConfigurationRefreshed;
            v1ConfigurationManager.RequestRefresh();

            actualIssuer = v1AadIssuerValidator.Validate(v1TokenIssuer, v1JwtSecurityToken, new TokenValidationParameters { ValidateWithLKG = true });
            validationResult = ValidateIssuerSync(
               v1TokenIssuer,
               v1JwtSecurityToken,
               aadIssuerValidator,
               true);

            Assert.True(validationResult.Succeeded);
            IdentityComparer.AreEqual(v1TokenIssuer, validationResult.Result.Issuer, context);
            IdentityComparer.AreEqual(v1TokenIssuer, actualIssuer, context);
            TestUtilities.AssertFailIfErrors(context);

            // validating cross versions also validates with LKG
            actualIssuer = aadIssuerValidator.Validate(v1TokenIssuer, v1JwtSecurityToken, new TokenValidationParameters { ValidateWithLKG = true });
            validationResult = ValidateIssuerSync(
               v1TokenIssuer,
               v1JwtSecurityToken,
               aadIssuerValidator,
               true);

            Assert.True(validationResult.Succeeded);
            IdentityComparer.AreEqual(v1TokenIssuer, validationResult.Result.Issuer, context);
            IdentityComparer.AreEqual(v1TokenIssuer, actualIssuer, context);
            TestUtilities.AssertFailIfErrors(context);

            // if LKG not valid validation fails
            //    set ConfigurationManager lkg lifetime to 1ms
            //    validate successfully to set LKG
            //    wait 1ms, validate with expired LKG
            v1ConfigurationManager.RefreshedConfiguration = v1Configuration;
            v1ConfigurationManager.RequestRefresh();

            v1ConfigurationManager.LastKnownGoodLifetime = TimeSpan.FromMilliseconds(1);
            actualIssuer = aadIssuerValidator.Validate(v1TokenIssuer, v1JwtSecurityToken, new TokenValidationParameters());
            validationResult = ValidateIssuerSync(
               v1TokenIssuer,
               v1JwtSecurityToken,
               aadIssuerValidator);

            Thread.Sleep(TimeSpan.FromMilliseconds(1));

            var securityExceptionThrown = false;
            var exceptionMessage = string.Empty;
            try
            {
                validationResult = ValidateIssuerSync(
                   v1TokenIssuer,
                   v1JwtSecurityToken,
                   aadIssuerValidator,
                   true);

                _ = aadIssuerValidator.Validate(v1TokenIssuer, v1JwtSecurityToken, new TokenValidationParameters { ValidateWithLKG = true });
            }
            catch (SecurityTokenInvalidIssuerException securityException)
            {
                securityExceptionThrown = true;
                exceptionMessage = securityException.Message;
            }

            Assert.False(validationResult.Succeeded);
            IdentityComparer.AreEqual(
                string.Format(LogMessages.IDX40001, "https://sts.windows.net/10c419d4-4a50-45b2-aa4e-919fb84df24f/"),
                validationResult.Error.MessageDetail.Message,
                context);
            IdentityComparer.AreEqual(true, securityExceptionThrown, context);
            IdentityComparer.AreEqual(string.Format(LogMessages.IDX40001, "https://sts.windows.net/10c419d4-4a50-45b2-aa4e-919fb84df24f/"),
                exceptionMessage,
                context);

            TestUtilities.AssertFailIfErrors(context);
        }

        private static ValidationResult<ValidatedIssuer, IssuerValidationError> ValidateIssuerSync(
            string issuerFromToken,
            SecurityToken securityToken,
            AadIssuerValidator validator,
            bool validateWithLKG = false)
        {
            ValidationParameters validationParameters = new ValidationParameters() { ValidateWithLKG = validateWithLKG };
            CallContext callContext = new CallContext();

            return validator.ValidateIssuerSync(
                issuerFromToken,
                securityToken,
                validationParameters,
                callContext,
                CancellationToken.None);
        }

        private static ValidationResult<ValidatedIssuer, IssuerValidationError> ValidateIssuerSync(
            string issuerFromToken,
            string addIssuerToValidationParameters,
            SecurityToken securityToken,
            AadIssuerValidator validator)
        {
            ValidationParameters validationParameters = new ValidationParameters();
            validationParameters.ValidIssuers.Add(addIssuerToValidationParameters);
            CallContext callContext = new CallContext();

            return validator.ValidateIssuerSync(
                issuerFromToken,
                securityToken,
                validationParameters,
                callContext,
                CancellationToken.None);
        }

        private static ValidationResult<ValidatedIssuer, IssuerValidationError> ValidateIssuerSync(
            string issuerFromToken,
            BaseConfigurationManager configurationManager,
            SecurityToken securityToken,
            AadIssuerValidator validator)
        {
            ValidationParameters validationParameters = new ValidationParameters();
            validationParameters.ConfigurationManager = configurationManager;

            return validator.ValidateIssuerSync(
                issuerFromToken,
                securityToken,
                validationParameters,
                new CallContext(),
                CancellationToken.None);
        }
    }
}
