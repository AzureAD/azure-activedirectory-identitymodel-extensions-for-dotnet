using Microsoft.IdentityModel.TestUtils;

namespace System.ServiceModel.Federation.Tests
{
    public class MessageSecurityVersionTheoryData : TheoryDataBase
    {
        public MessageSecurityVersion IssuerBindingSecurityVersion { get; set; }

        public MessageSecurityVersion DefaultMessageSecurityVersion { get; set; }

        public MessageSecurityVersion OuterBindingSecurityVersion { get; set; }

        public MessageSecurityVersion ExpectedMessageSecurityVersion { get; set; }
    }
}
