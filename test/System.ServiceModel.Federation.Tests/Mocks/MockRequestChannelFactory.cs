// Licensed to the .NET Foundation under one or more agreements.
// The .NET Foundation licenses this file to you under the MIT license.
// See the LICENSE file in the project root for more information.

using System.ServiceModel.Channels;
using System.ServiceModel.Description;

namespace System.ServiceModel.Federation.Tests.Mocks
{
    class MockRequestChannelFactory: ChannelFactory<IRequestChannel>
    {
        private MockResponseSettings _responseSettings;

        public MockResponseSettings ResponseSettings
        {
            get => _responseSettings;
            set
            {
                _responseSettings = value;
                Channel = new MockRequestChannel(_responseSettings);
            }
        }

        public MockRequestChannel Channel { get; private set; } = new MockRequestChannel(null);

        public MockRequestChannelFactory() : base(new ServiceEndpoint(new ContractDescription("Name")) { Address = new EndpointAddress("http://localhost") })
        { }

        public override IRequestChannel CreateChannel(EndpointAddress address, Uri via) => Channel;
    }
}
