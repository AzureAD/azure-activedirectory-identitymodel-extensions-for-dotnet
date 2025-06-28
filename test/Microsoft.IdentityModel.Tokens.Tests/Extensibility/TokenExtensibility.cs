// Copyright (c) Microsoft Corporation. All rights reserved.
// Licensed under the MIT License.

using System.Threading.Tasks;
using Microsoft.IdentityModel.JsonWebTokens;
using Microsoft.IdentityModel.TestUtils;
using Microsoft.IdentityModel.Tokens.Saml;
using Microsoft.IdentityModel.Tokens.Saml2;
using Xunit;

#nullable enable
namespace Microsoft.IdentityModel.Tokens.Extensibility.Tests
{
    public class TokenExtensibility
    {
        [Theory, MemberData(nameof(JwtExtensibilityTestCases), DisableDiscoveryEnumeration = true)]
        public async Task JwtExtensibilityTests(ExtensibilityTheoryData theoryData)
        {
            await ExtensibilityRunner.RunTest(theoryData, this, nameof(TokenExtensibility));
        }

        public static TheoryData<ExtensibilityTheoryData> JwtExtensibilityTestCases()
        {
            TheoryData<ExtensibilityTheoryData> theoryData = new();
            var tokenHandler = new JsonWebTokenHandler();
            var token = Default.JsonWebToken();

            return GenerateTestCases(tokenHandler, token);
        }

        [Theory, MemberData(nameof(Saml2ExtensibilityTestCases), DisableDiscoveryEnumeration = true)]
        public async Task Saml2ExtensibilityTests(ExtensibilityTheoryData theoryData)
        {
            await ExtensibilityRunner.RunTest(theoryData, this, nameof(TokenExtensibility));
        }

        public static TheoryData<ExtensibilityTheoryData> Saml2ExtensibilityTestCases()
        {
            TheoryData<ExtensibilityTheoryData> theoryData = new();
            var tokenHandler = new Saml2SecurityTokenHandler();
            var token = Default.Saml2SecurityToken();

            return GenerateTestCases(tokenHandler, token);
        }


        [Theory, MemberData(nameof(SamlExtensibilityTestCases), DisableDiscoveryEnumeration = true)]
        public async Task SamlExtensibilityTests(ExtensibilityTheoryData theoryData)
        {
            await ExtensibilityRunner.RunTest(theoryData, this, nameof(TokenExtensibility));
        }

        public static TheoryData<ExtensibilityTheoryData> SamlExtensibilityTestCases()
        {
            TheoryData<ExtensibilityTheoryData> theoryData = new();
            var tokenHandler = new SamlSecurityTokenHandler();
            var token = Default.SamlSecurityToken();

            return GenerateTestCases(tokenHandler, token);
        }


        public static TheoryData<ExtensibilityTheoryData> GenerateTestCases(TokenHandler tokenHandler, SecurityToken token)
        {
            TheoryData<ExtensibilityTheoryData> theoryData = new();

            foreach (var test in ExtensibilityTestProvider.GenerateAlgorithmTestCases(tokenHandler, token, "http://www.w3.org/2001/04/xmldsig-more#rsa-sha256"))
                theoryData.Add(test);

            foreach (var test in ExtensibilityTestProvider.GenerateAudienceTestCases(tokenHandler, token))
                theoryData.Add(test);

            foreach (var test in ExtensibilityTestProvider.GenerateIssuerTestCases(tokenHandler, token))
                theoryData.Add(test);

            foreach (var test in ExtensibilityTestProvider.GenerateIssuerSigningKeyTestCases(tokenHandler, token))
                theoryData.Add(test);

            foreach (var test in ExtensibilityTestProvider.GenerateLifetimeTestCases(tokenHandler, token))
                theoryData.Add(test);

            foreach (var test in ExtensibilityTestProvider.GenerateSignatureTestCases(tokenHandler, token))
                theoryData.Add(test);

            foreach (var test in ExtensibilityTestProvider.GenerateTokenReplayTestCases(tokenHandler, token))
                theoryData.Add(test);

            // SAML and SAML2 do not have token type extensibility.
            if (tokenHandler is JsonWebTokenHandler)
            {
                foreach (var test in ExtensibilityTestProvider.GenerateTokenTypeTestCases(tokenHandler, token))
                    theoryData.Add(test);
            }

            return theoryData;
        }
    }
}
#nullable restore
