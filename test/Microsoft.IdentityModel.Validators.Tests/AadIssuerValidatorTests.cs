// Copyright (c) Microsoft Corporation. All rights reserved.
// Licensed under the MIT License.
using Xunit;

namespace Microsoft.IdentityModel.Validators.Tests
{
    public class AadIssuerValidatorTests
    {
        [Theory]
        [InlineData(ValidatorConstants.AadInstance + AadIssuerValidator.TenantIdTemplate, ValidatorConstants.AadInstance + ValidatorConstants.TenantIdAsGuid, true)]
        [InlineData(ValidatorConstants.AadInstancePPE + AadIssuerValidator.TenantIdTemplate, ValidatorConstants.AadInstance + ValidatorConstants.TenantIdAsGuid, false)]
        [InlineData("", ValidatorConstants.AadInstance + ValidatorConstants.TenantIdAsGuid, false)]
        [InlineData(ValidatorConstants.AadInstance + AadIssuerValidator.TenantIdTemplate, "", false)]
        public static void IsValidIssuer_CanValidateTemplatedIssuers(string templatedIssuer, string issuer, bool expectedResult)
        {
            // act
            var result = AadIssuerValidator.IsValidIssuer(templatedIssuer, ValidatorConstants.TenantIdAsGuid, issuer);

            // assert
            Assert.Equal(expectedResult, result);
        }
    }
}
