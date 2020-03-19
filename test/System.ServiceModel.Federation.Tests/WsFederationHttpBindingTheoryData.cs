using Microsoft.IdentityModel.TestUtils;

namespace System.ServiceModel.Federation.Tests
{
    public class WsFederationHttpBindingTheoryData: TheoryDataBase
    {
        public string RequestContext { get; set; }
        public Microsoft.IdentityModel.Tokens.SecurityKey IssuedTokenParametersSecurityKey { get; set; }
        public System.IdentityModel.Tokens.SecurityKeyType IssuedSecurityTokenParametersKeyType { get; set; }
    }
}
