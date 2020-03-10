using System.ServiceModel.Channels;
using System.ServiceModel.Description;

namespace System.ServiceModel.Federation.Tests.Mocks
{
    class MockRequestChannelFactory: ChannelFactory<IRequestChannel>
    {
        public MockRequestChannelFactory() : base(new ServiceEndpoint(new ContractDescription("Name")) { Address = new EndpointAddress("http://localhost") })
        { }

        public override IRequestChannel CreateChannel(EndpointAddress address, Uri via)
        {
            return new MockRequestChannel();
        }
    }
}
