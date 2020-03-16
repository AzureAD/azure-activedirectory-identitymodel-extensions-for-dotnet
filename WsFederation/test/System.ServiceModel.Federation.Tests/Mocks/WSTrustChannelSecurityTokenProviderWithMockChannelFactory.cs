using System.IdentityModel.Selectors;
using System.ServiceModel.Channels;
using System.ServiceModel.Security.Tokens;

namespace System.ServiceModel.Federation.Tests.Mocks
{
    /// <summary>
    /// Test class that overrides WSTrustChannelSecurityTokenProvider's CreateChannelFactory method
    /// to allow testing WSTrustChannelSecurityTokenProvider without actually sending any WCF messages.
    /// </summary>
    class WSTrustChannelSecurityTokenProviderWithMockChannelFactory : WSTrustChannelSecurityTokenProvider
    {
        public WSTrustChannelSecurityTokenProviderWithMockChannelFactory(SecurityTokenRequirement tokenRequirement) :
            base(tokenRequirement)
        { }

        protected override ChannelFactory<IRequestChannel> CreateChannelFactory(IssuedSecurityTokenParameters issuedTokenParameters) =>
            new MockRequestChannelFactory();
    }
}
