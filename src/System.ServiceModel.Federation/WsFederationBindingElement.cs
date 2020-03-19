using System.ServiceModel.Channels;

namespace System.ServiceModel.Federation
{
    internal class WsFederationBindingElement : BindingElement
    {
        public WsFederationBindingElement(IssuedTokenParameters issuedTokenParameters, SecurityBindingElement securityBindingElement)
        {
            IssuedTokenParameters = issuedTokenParameters;
            SecurityBindingElement = securityBindingElement;
        }

        public IssuedTokenParameters IssuedTokenParameters { get; }

        public SecurityBindingElement SecurityBindingElement { get; }

        public string WSTrustContext
        {
            get;
            set;
        }

        public override BindingElement Clone()
        {
            return new WsFederationBindingElement(IssuedTokenParameters, SecurityBindingElement)
            {
                WSTrustContext = WSTrustContext
            };
        }

        public override T GetProperty<T>(BindingContext context)
        {
            return SecurityBindingElement.GetProperty<T>(context);
        }

        public override IChannelFactory<TChannel> BuildChannelFactory<TChannel>(BindingContext context)
        {
            if (context.BindingParameters.Contains(typeof(WsTrustChannelClientCredentials)))
            {
                var credentials = context.BindingParameters[typeof(WsTrustChannelClientCredentials)] as WsTrustChannelClientCredentials;
                credentials.RequestContext = WSTrustContext;
            }

            var channelFactory = base.BuildChannelFactory<TChannel>(context);
            return channelFactory;
        }
    }
}
