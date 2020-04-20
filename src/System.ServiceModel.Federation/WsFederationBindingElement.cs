using System.Collections.ObjectModel;
using System.ServiceModel.Channels;
using System.ServiceModel.Description;
using System.ServiceModel.Security.Tokens;

namespace System.ServiceModel.Federation
{
    internal class WsFederationBindingElement : BindingElement
    {
        public WsFederationBindingElement(IssuedSecurityTokenParameters issuedTokenParameters, SecurityBindingElement securityBindingElement)
        {
            IssuedSecurityTokenParameters = issuedTokenParameters;
            SecurityBindingElement = securityBindingElement;
        }

        public IssuedSecurityTokenParameters IssuedSecurityTokenParameters { get; }

        public SecurityBindingElement SecurityBindingElement { get; }

        /// <summary>
        /// Gets or sets a context string used in outgoing WsTrust requests that may be useful for correlating requests.
        /// </summary>
        public string WSTrustContext
        {
            get;
            set;
        }

        public override BindingElement Clone()
        {
            return new WsFederationBindingElement(IssuedSecurityTokenParameters, SecurityBindingElement)
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
            WsTrustChannelClientCredentials trustCredentials = Find<WsTrustChannelClientCredentials>(context.BindingParameters);
            if (trustCredentials == null)
            {
                var clientCredentials = Find<ClientCredentials>(context.BindingParameters);
                if (clientCredentials != null)
                {
                    trustCredentials = new WsTrustChannelClientCredentials(clientCredentials);
                    context.BindingParameters.Remove(typeof(ClientCredentials));
                    context.BindingParameters.Add(trustCredentials);
                }
                else
                {
                    trustCredentials = new WsTrustChannelClientCredentials();
                    context.BindingParameters.Add(trustCredentials);
                }
            }

            trustCredentials.RequestContext = WSTrustContext;
            var channelFactory = base.BuildChannelFactory<TChannel>(context);
            return channelFactory;
        }

        private T Find<T>(BindingParameterCollection bindingParameterCollection)
        {
            for (int i = 0; i < bindingParameterCollection.Count; i++)
            {
                object settings = bindingParameterCollection[i];
                if (settings is T)
                {
                    return (T)settings;
                }
            }

            return default(T);
        }
    }
}
