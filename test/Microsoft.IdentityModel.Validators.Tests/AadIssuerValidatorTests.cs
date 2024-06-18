// Copyright (c) Microsoft Corporation. All rights reserved.
// Licensed under the MIT License.

using Microsoft.IdentityModel.TestUtils;
using Xunit;

namespace Microsoft.IdentityModel.Validators.Tests
{
    public class AadIssuerValidatorTests
    {
        [Theory, MemberData(nameof(AadIssuerValidationTestCases))]
        public static void IsValidIssuer_CanValidateTemplatedIssuers(AadIssuerValidatorTheoryData theoryData)
        {
            // act
            var result = AadIssuerValidator.IsValidIssuer(theoryData.TemplatedIssuer, theoryData.TenantIdClaim, theoryData.TokenIssuer);

            // assert
            Assert.Equal(theoryData.ExpectedResult, result);
        }

        public static TheoryData<AadIssuerValidatorTheoryData> AadIssuerValidationTestCases()
        {
            var theoryData = new TheoryData<AadIssuerValidatorTheoryData>
            {
                new AadIssuerValidatorTheoryData("CompareTokenIssuer_V1TemplateWithV1Issuer_Success")
                {
                    TemplatedIssuer = ValidatorConstants.AadIssuerV1CommonAuthority,
                    TokenIssuer = ValidatorConstants.V1Issuer,
                    TenantIdClaim = ValidatorConstants.TenantIdAsGuid,
                    ExpectedResult = true,
                },
                new AadIssuerValidatorTheoryData("ValidateIssuer_V1TemplateWithV2Issuer_Failure")
                {
                    TemplatedIssuer = ValidatorConstants.AadIssuerV1CommonAuthority,
                    TokenIssuer = ValidatorConstants.AadIssuer,
                    TenantIdClaim = ValidatorConstants.TenantIdAsGuid,
                    ExpectedResult = false,
                },
                new AadIssuerValidatorTheoryData("ValidateIssuer_V2TemplateWithV1Issuer_Failure")
                {
                    TemplatedIssuer = ValidatorConstants.AadIssuerV2CommonAuthority,
                    TokenIssuer = ValidatorConstants.V1Issuer,
                    TenantIdClaim = ValidatorConstants.TenantIdAsGuid,
                    ExpectedResult = false,
                },
                new AadIssuerValidatorTheoryData("ValidateIssuer_V2TemplateWithV2Issuer_Success")
                {
                    TemplatedIssuer = ValidatorConstants.AadIssuerV2CommonAuthority,
                    TokenIssuer = ValidatorConstants.AadIssuer,
                    TenantIdClaim = ValidatorConstants.TenantIdAsGuid,
                    ExpectedResult = true,
                },
                new AadIssuerValidatorTheoryData("ValidateIssuer_NullTemplate_Failure")
                {
                    TemplatedIssuer = ValidatorConstants.AadIssuerV1CommonAuthority,
                    TokenIssuer = "",
                    TenantIdClaim = ValidatorConstants.TenantIdAsGuid,
                    ExpectedResult = false,
                },

                new AadIssuerValidatorTheoryData("ValidateIssuer_NullIssuer_Failure")
                {
                    TemplatedIssuer = ValidatorConstants.AadIssuerV1CommonAuthority,
                    TokenIssuer = "",
                    TenantIdClaim = ValidatorConstants.TenantIdAsGuid,
                    ExpectedResult = false,
                },
                new AadIssuerValidatorTheoryData("ValidateIssuer_NullTenantId_Failure")
                {
                    TemplatedIssuer = ValidatorConstants.AadIssuerV1CommonAuthority,
                    TokenIssuer = ValidatorConstants.AadIssuer,
                    TenantIdClaim = "",
                    ExpectedResult = false,
                },
                new AadIssuerValidatorTheoryData("ValidateIssuer_PPETemplateWithV1Issuer_Failure")
                {
                    TemplatedIssuer = ValidatorConstants.AadInstancePPE + "/" + AadIssuerValidator.TenantIdTemplate,
                    TokenIssuer =  ValidatorConstants.AadInstance + "/" + ValidatorConstants.TenantIdAsGuid,
                    TenantIdClaim = ValidatorConstants.TenantIdAsGuid,
                    ExpectedResult = false,
                },
                new AadIssuerValidatorTheoryData("ValidateIssuerSigningKey_V2SigningKeyIssuer_V1TokenIssuer_Failure")
                {
                    TemplatedIssuer = ValidatorConstants.AadIssuerV2CommonAuthority,
                    TokenIssuer =  ValidatorConstants.V1Issuer,
                    TenantIdClaim = ValidatorConstants.TenantIdAsGuid,
                    ExpectedResult = false,
                },
                new AadIssuerValidatorTheoryData("ValidateIssuerSigningKey_V2SigningKeyIssuer_V2TokenIssuer_Success")
                {
                    TemplatedIssuer = ValidatorConstants.AadIssuerV2CommonAuthority,
                    TokenIssuer =  ValidatorConstants.AadIssuer,
                    TenantIdClaim = ValidatorConstants.TenantIdAsGuid,
                    ExpectedResult = true,
                },
                new AadIssuerValidatorTheoryData("ValidateIssuerSigningKey_MalformedV2TokenIssuer_Failure")
                {
                    TemplatedIssuer = ValidatorConstants.AadIssuerV2CommonAuthority,
                    TokenIssuer =  "https://login.microsoftonline.com/{tenantid}/v2.0",
                    TenantIdClaim = ValidatorConstants.TenantIdAsGuid,
                    ExpectedResult = false,
                }
            };

            return theoryData;
        }
    }

    public class AadIssuerValidatorTheoryData : TheoryDataBase
    {
        public AadIssuerValidatorTheoryData()
        {
        }

        public AadIssuerValidatorTheoryData(string testId) : base(testId)
        {
        }

        public string TemplatedIssuer { get; set; }

        public string TokenIssuer { get; set; }

        public string TenantIdClaim { get; set; }

        public bool ExpectedResult { get; set; }
    }
}
