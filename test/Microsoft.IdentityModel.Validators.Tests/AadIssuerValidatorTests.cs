// Copyright (c) Microsoft Corporation. All rights reserved.
// Licensed under the MIT License.

using Microsoft.IdentityModel.TestUtils;
using Xunit;

namespace Microsoft.IdentityModel.Validators.Tests
{
    public class AadIssuerValidatorTests
    {
        [Theory, MemberData(nameof(AadIssuerValidationTestCases))]
        public static void IsValidIssuer_ValidatesIssuersCorrectly(AadIssuerValidatorTheoryData theoryData)
        {
            // Act
            var validationResult = AadIssuerValidator.IsValidIssuer(
                theoryData.TemplatedIssuer,
                theoryData.TenantIdClaim,
                theoryData.TokenIssuer);

            // Assert
            Assert.Equal(theoryData.ExpectedResult, validationResult);
        }

        public static TheoryData<AadIssuerValidatorTheoryData> AadIssuerValidationTestCases()
        {
            var theoryData = new TheoryData<AadIssuerValidatorTheoryData>
            {
                // Success cases
                new AadIssuerValidatorTheoryData("V1_Template_Matches_V1_Issuer_Success")
                {
                    TemplatedIssuer = ValidatorConstants.AadIssuerV1CommonAuthority,
                    TokenIssuer = ValidatorConstants.V1Issuer,
                    TenantIdClaim = ValidatorConstants.TenantIdAsGuid,
                    ExpectedResult = true,
                },
                new AadIssuerValidatorTheoryData("V2_Template_Matches_V2_Issuer_Success")
                {
                    TemplatedIssuer = ValidatorConstants.AadIssuerV2CommonAuthority,
                    TokenIssuer = ValidatorConstants.AadIssuer,
                    TenantIdClaim = ValidatorConstants.TenantIdAsGuid,
                    ExpectedResult = true,
                },

                // Failure cases
                new AadIssuerValidatorTheoryData("V1_Template_With_V2_Issuer_Failure")
                {
                    TemplatedIssuer = ValidatorConstants.AadIssuerV1CommonAuthority,
                    TokenIssuer = ValidatorConstants.AadIssuer,
                    TenantIdClaim = ValidatorConstants.TenantIdAsGuid,
                    ExpectedResult = false,
                },
                new AadIssuerValidatorTheoryData("V2_Template_With_V1_Issuer_Failure")
                {
                    TemplatedIssuer = ValidatorConstants.AadIssuerV2CommonAuthority,
                    TokenIssuer = ValidatorConstants.V1Issuer,
                    TenantIdClaim = ValidatorConstants.TenantIdAsGuid,
                    ExpectedResult = false,
                },
                new AadIssuerValidatorTheoryData("Null_TokenIssuer_Failure")
                {
                    TemplatedIssuer = ValidatorConstants.AadIssuerV1CommonAuthority,
                    TokenIssuer = "",
                    TenantIdClaim = ValidatorConstants.TenantIdAsGuid,
                    ExpectedResult = false,
                },
                new AadIssuerValidatorTheoryData("Null_TenantId_Failure")
                {
                    TemplatedIssuer = ValidatorConstants.AadIssuerV1CommonAuthority,
                    TokenIssuer = ValidatorConstants.AadIssuer,
                    TenantIdClaim = "",
                    ExpectedResult = false,
                },
                new AadIssuerValidatorTheoryData("PPE_Template_With_V1_Issuer_Failure")
                {
                    TemplatedIssuer = ValidatorConstants.AadInstancePPE + "/" + AadIssuerValidator.TenantIdTemplate,
                    TokenIssuer =  ValidatorConstants.AadInstance + "/" + ValidatorConstants.TenantIdAsGuid,
                    TenantIdClaim = ValidatorConstants.TenantIdAsGuid,
                    ExpectedResult = false,
                },
                new AadIssuerValidatorTheoryData("Malformed_V2_TokenIssuer_Failure")
                {
                    TemplatedIssuer = ValidatorConstants.AadIssuerV2CommonAuthority,
                    TokenIssuer = "https://login.microsoftonline.com/{tenantid}/v2.0",
                    TenantIdClaim = ValidatorConstants.TenantIdAsGuid,
                    ExpectedResult = false,
                }
            };

            return theoryData;
        }
    }

    public class AadIssuerValidatorTheoryData : TheoryDataBase
    {
        public AadIssuerValidatorTheoryData() {}

        public AadIssuerValidatorTheoryData(string testId) : base(testId) { }

        public string TemplatedIssuer { get; set; }

        public string TokenIssuer { get; set; }

        public string TenantIdClaim { get; set; }

        public bool ExpectedResult { get; set; }
    }
}
