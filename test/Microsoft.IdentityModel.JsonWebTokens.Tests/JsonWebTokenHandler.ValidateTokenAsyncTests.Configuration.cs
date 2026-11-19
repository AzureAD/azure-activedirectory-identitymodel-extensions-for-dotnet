// Copyright (c) Microsoft Corporation. All rights reserved.
// Licensed under the MIT License.

using System.Threading;
using System.Threading.Tasks;
using Microsoft.IdentityModel.Protocols.OpenIdConnect;
using Microsoft.IdentityModel.TestUtils;
using Microsoft.IdentityModel.Tokens;
using Microsoft.IdentityModel.Tokens.Experimental;
using Moq;
using Xunit;

namespace Microsoft.IdentityModel.JsonWebTokens.Tests;

public class JsonWebTokenHandlerConfigurationTests
{
    [Theory]
    [InlineData(false)]
    [InlineData(true)]
    public async Task ValidateTokenAsync_CurrentConfigurationIsNotRetrievedAgain(bool configurationAvailable)
    {
        // Arrange
        BaseConfiguration selectedConfiguration = configurationAvailable ? CreateConfiguration(Default.Issuer) : null;
        BaseConfiguration subsequentConfiguration = CreateConfiguration("https://subsequent-issuer.example");
        Mock<BaseConfigurationManager> configurationManager = new Mock<BaseConfigurationManager>();
        configurationManager.Object.UseLastKnownGoodConfiguration = false;
        int configurationReads = 0;
        configurationManager
            .Setup(manager => manager.GetBaseConfigurationAsync(It.IsAny<CancellationToken>()))
            .ReturnsAsync(() => ++configurationReads == 1 ? selectedConfiguration : subsequentConfiguration);
        ValidationParameters validationParameters = CreateValidationParameters(configurationManager.Object);
        if (!configurationAvailable)
        {
            validationParameters.ValidIssuers.Add(Default.Issuer);
            validationParameters.SigningKeys.Add(KeyingMaterial.DefaultSymmetricSigningCreds_256_Sha2.Key);
        }

        // Act
        ValidationResult<ValidatedToken, ValidationError> result = await new JsonWebTokenHandler().ValidateTokenAsync(
            CreateToken(false), validationParameters, new CallContext(), CancellationToken.None);

        // Assert
        Assert.True(result.Succeeded, result.Error?.Message);
        Assert.Equal(Default.Issuer, result.Result.ValidatedIssuer.Value.Issuer);
        Assert.Equal(
            configurationAvailable ? IssuerValidationSource.IssuerMatchedConfiguration : IssuerValidationSource.IssuerMatchedValidationParameters,
            result.Result.ValidatedIssuer.Value.ValidationSource);
        Assert.Equal(1, configurationReads);
        configurationManager.Verify(manager => manager.RequestRefresh(), Times.Never);
    }

    [Theory]
    [InlineData(false)]
    [InlineData(true)]
    public async Task ValidateTokenAsync_RefreshUsesSelectedConfiguration(bool encryptToken)
    {
        // Arrange
        BaseConfiguration currentConfiguration = new OpenIdConnectConfiguration { Issuer = "https://old-issuer.example" };
        BaseConfiguration refreshedConfiguration = CreateConfiguration(Default.Issuer);
        BaseConfiguration subsequentConfiguration = CreateConfiguration("https://subsequent-issuer.example");
        Mock<BaseConfigurationManager> configurationManager = new Mock<BaseConfigurationManager>();
        configurationManager.Object.UseLastKnownGoodConfiguration = false;
        int configurationReads = 0;
        configurationManager
            .Setup(manager => manager.GetBaseConfigurationAsync(It.IsAny<CancellationToken>()))
            .ReturnsAsync(() => ++configurationReads == 1 ? currentConfiguration :
                configurationReads == 2 ? refreshedConfiguration : subsequentConfiguration);
        ValidationParameters validationParameters = CreateValidationParameters(configurationManager.Object);

        // Act
        ValidationResult<ValidatedToken, ValidationError> result = await new JsonWebTokenHandler().ValidateTokenAsync(
            CreateToken(encryptToken), validationParameters, new CallContext(), CancellationToken.None);

        // Assert
        AssertValidatedConfiguration(result, refreshedConfiguration);
        Assert.Same(refreshedConfiguration, configurationManager.Object.LastKnownGoodConfiguration);
        Assert.Equal(2, configurationReads);
        configurationManager.Verify(manager => manager.RequestRefresh(), Times.Once);
    }

    [Theory]
    [InlineData(false)]
    [InlineData(true)]
    public async Task ValidateTokenAsync_LastKnownGoodUsesSelectedConfiguration(bool encryptToken)
    {
        // Arrange
        BaseConfiguration currentConfiguration = new OpenIdConnectConfiguration { Issuer = "https://current-issuer.example" };
        BaseConfiguration lastKnownGoodConfiguration = CreateConfiguration(Default.Issuer);
        Mock<BaseConfigurationManager> configurationManager = new Mock<BaseConfigurationManager>();
        configurationManager.Object.LastKnownGoodConfiguration = lastKnownGoodConfiguration;
        configurationManager
            .Setup(manager => manager.GetBaseConfigurationAsync(It.IsAny<CancellationToken>()))
            .ReturnsAsync(currentConfiguration);
        ValidationParameters validationParameters = CreateValidationParameters(configurationManager.Object);

        // Act
        ValidationResult<ValidatedToken, ValidationError> result = await new JsonWebTokenHandler().ValidateTokenAsync(
            CreateToken(encryptToken), validationParameters, new CallContext(), CancellationToken.None);

        // Assert
        AssertValidatedConfiguration(result, lastKnownGoodConfiguration);
        Assert.True(validationParameters.ValidateWithLKG);
        Assert.Same(lastKnownGoodConfiguration, configurationManager.Object.LastKnownGoodConfiguration);
        configurationManager.Verify(
            manager => manager.GetBaseConfigurationAsync(It.IsAny<CancellationToken>()), Times.Exactly(2));
    }

    [Theory]
    [InlineData(false)]
    [InlineData(true)]
    public async Task ValidateTokenAsync_DoesNotMixConfigurationIssuersAndSigningKeys(bool encryptToken)
    {
        // Arrange
        BaseConfiguration currentConfiguration = new OpenIdConnectConfiguration { Issuer = Default.Issuer };
        BaseConfiguration lastKnownGoodConfiguration = CreateConfiguration("https://other-issuer.example");
        Mock<BaseConfigurationManager> configurationManager = new Mock<BaseConfigurationManager>();
        configurationManager.Object.LastKnownGoodConfiguration = lastKnownGoodConfiguration;
        configurationManager
            .Setup(manager => manager.GetBaseConfigurationAsync(It.IsAny<CancellationToken>()))
            .ReturnsAsync(currentConfiguration);
        ValidationParameters validationParameters = CreateValidationParameters(configurationManager.Object);

        // Act
        ValidationResult<ValidatedToken, ValidationError> result = await new JsonWebTokenHandler().ValidateTokenAsync(
            CreateToken(encryptToken), validationParameters, new CallContext(), CancellationToken.None);

        // Assert
        Assert.False(result.Succeeded);
        IssuerValidationError error = Assert.IsType<IssuerValidationError>(result.Error);
        Assert.Same(IssuerValidationFailure.ValidationFailed, error.FailureType);
        Assert.True(validationParameters.ValidateWithLKG);
        configurationManager.Verify(
            manager => manager.GetBaseConfigurationAsync(It.IsAny<CancellationToken>()), Times.Exactly(2));
    }

    private static BaseConfiguration CreateConfiguration(string issuer)
    {
        BaseConfiguration configuration = new OpenIdConnectConfiguration { Issuer = issuer };
        configuration.SigningKeys.Add(KeyingMaterial.DefaultSymmetricSigningCreds_256_Sha2.Key);
        return configuration;
    }

    private static ValidationParameters CreateValidationParameters(BaseConfigurationManager configurationManager)
    {
        ValidationParameters validationParameters = new ValidationParameters { ConfigurationManager = configurationManager };
        validationParameters.ValidAudiences.Add(Default.Audience);
        validationParameters.DecryptionKeys.Add(KeyingMaterial.DefaultSymmetricEncryptingCreds_Aes128_Sha2.Key);
        return validationParameters;
    }

    private static string CreateToken(bool encryptToken)
    {
        return new JsonWebTokenHandler().CreateToken(new SecurityTokenDescriptor
        {
            Issuer = Default.Issuer,
            Audience = Default.Audience,
            SigningCredentials = KeyingMaterial.DefaultSymmetricSigningCreds_256_Sha2,
            EncryptingCredentials = encryptToken ? KeyingMaterial.DefaultSymmetricEncryptingCreds_Aes128_Sha2 : null
        });
    }

    private static void AssertValidatedConfiguration(
        ValidationResult<ValidatedToken, ValidationError> result, BaseConfiguration configuration)
    {
        Assert.True(result.Succeeded, result.Error?.Message);
        Assert.Equal(Default.Issuer, result.Result.ValidatedIssuer.Value.Issuer);
        Assert.Equal(IssuerValidationSource.IssuerMatchedConfiguration, result.Result.ValidatedIssuer.Value.ValidationSource);
        Assert.Same(Assert.Single(configuration.SigningKeys), result.Result.ValidatedSignatureKey);
    }
}
