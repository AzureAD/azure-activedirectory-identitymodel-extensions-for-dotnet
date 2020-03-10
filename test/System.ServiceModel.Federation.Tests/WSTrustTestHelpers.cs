using System.IdentityModel.Selectors;
using System.IdentityModel.Tokens;
using System.ServiceModel.Channels;
using System.ServiceModel.Security.Tokens;
using Microsoft.IdentityModel.Tokens.Saml2;

namespace System.ServiceModel.Federation.Tests
{
    static class WSTrustTestHelpers
    {
        const string TargetAddressUri = "http://schemas.microsoft.com/ws/2006/05/servicemodel/securitytokenrequirement/TargetAddress";
        const string IssuedTokenParametersUri = "http://schemas.microsoft.com/ws/2006/05/servicemodel/securitytokenrequirement/IssuedSecurityTokenParameters";

        public static SecurityTokenRequirement CreateSecurityRequirement(
            Binding issuerBinding,
            string issuerAddress = "http://localhost",
            string tokenType = Saml2Constants.OasisWssSaml2TokenProfile11,
            string targetAddress = "http://localhost",
            SecurityKeyType keyType = SecurityKeyType.BearerKey)
        {
            var requirements = new SecurityTokenRequirement
            {
                TokenType = tokenType
            };

            var issuedTokenParameters = new IssuedSecurityTokenParameters
            {
                IssuerAddress = new EndpointAddress(issuerAddress),
                KeyType = keyType,
                IssuerBinding = issuerBinding
            };

            requirements.Properties.Add(TargetAddressUri, new EndpointAddress(targetAddress));
            requirements.Properties.Add(IssuedTokenParametersUri, issuedTokenParameters);

            return requirements;
        }
    }
}
