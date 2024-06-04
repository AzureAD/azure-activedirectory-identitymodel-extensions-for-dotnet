// Copyright (c) Microsoft Corporation. All rights reserved.
// Licensed under the MIT License.
using System;
using Xunit;

namespace Microsoft.IdentityModel.Validators.Tests
{
    public class AadIssuerValidatorTests
    {
        [Fact]
        public static void IssuersWithTemplatesAreEqualTests_EqualIssuers()
        { 
            // arrange
            var issuer1Template = "{tenantId}";
            var issuer1 = ValidatorConstants.AadInstance + issuer1Template;
            var issuer2Template = ValidatorConstants.TenantIdAsGuid;
            var issuer2 = ValidatorConstants.AadInstance + issuer2Template;
            int templateStartIndex = issuer1.IndexOf(issuer1Template);

            // act
            var result = AadIssuerValidator.IssuersWithTemplatesAreEqual(
                issuer1.AsSpan(), issuer1Template.AsSpan(), templateStartIndex, issuer2.AsSpan(), issuer2Template.AsSpan());

            // assert
            Assert.True(result);
        }

        [Fact]
        public static void IssuersWithTemplatesAreEqualTests_UnequalIssuers()
        {
            // arrange
            var issuer1Template = "{tenantId}";
            var issuer1 = ValidatorConstants.AadInstancePPE + issuer1Template;
            var issuer2Template = ValidatorConstants.TenantIdAsGuid;
            var issuer2 = ValidatorConstants.AadInstance + issuer2Template;
            int templateStartIndex = issuer1.IndexOf(issuer1Template);

            // act
            var result = AadIssuerValidator.IssuersWithTemplatesAreEqual(
                issuer1.AsSpan(), issuer1Template.AsSpan(), templateStartIndex, issuer2.AsSpan(), issuer2Template.AsSpan());

            // assert
            Assert.False(result);
        }
    }
}
