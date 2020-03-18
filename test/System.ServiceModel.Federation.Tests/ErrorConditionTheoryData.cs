using Microsoft.IdentityModel.TestUtils;

namespace System.ServiceModel.Federation.Tests
{
    public class ErrorConditionTheoryData : TheoryDataBase
    {
        public Action<WSTrustChannelSecurityTokenProvider> Action { get; set; }
    }
}
