// Licensed to the .NET Foundation under one or more agreements.
// The .NET Foundation licenses this file to you under the MIT license.
// See the LICENSE file in the project root for more information.

#pragma warning disable 1591

using System.IdentityModel.Tokens;
using System.ServiceModel.Channels;
using Microsoft.IdentityModel.Tokens;

namespace System.ServiceModel.Federation
{
    public class WsFederationHttpBinding : WSHttpBinding
    {
        // binding is always TransportWithMessageCredentialy
        public WsFederationHttpBinding(IssuedTokenParameters issuedTokenParameters) : base(SecurityMode.TransportWithMessageCredential)
        {
            IssuedTokenParameters = issuedTokenParameters ?? throw new ArgumentNullException(nameof(issuedTokenParameters));
        }

        public IssuedTokenParameters IssuedTokenParameters
        {
            get;
        }

        private SecurityBindingElement SecurityBindingElement { get; set; }

        protected override SecurityBindingElement CreateMessageSecurity()
        {
            var issuedSecurityTokenParameters = IssuedTokenParameters.CreateIssuedSecurityTokenParameters();
            issuedSecurityTokenParameters.KeyType = IssuedTokenParameters.SecurityKey is AsymmetricSecurityKey
                                                        ? SecurityKeyType.AsymmetricKey
                                                        : IssuedTokenParameters.SecurityKey is Microsoft.IdentityModel.Tokens.SymmetricSecurityKey
                                                        ? SecurityKeyType.SymmetricKey
                                                        : SecurityKeyType.BearerKey;

            issuedSecurityTokenParameters.RequireDerivedKeys = false;
            var result = new TransportSecurityBindingElement
            {
                IncludeTimestamp = true,
                // TODO - brentsch - need to update versions available to include WSSecurity1.1 and WsTrust 1.3.
                MessageSecurityVersion = MessageSecurityVersion.WSSecurity10WSTrustFebruary2005WSSecureConversationFebruary2005WSSecurityPolicy11BasicSecurityProfile10
            };

            if (issuedSecurityTokenParameters.KeyType == SecurityKeyType.BearerKey)
                result.EndpointSupportingTokenParameters.Signed.Add(issuedSecurityTokenParameters);
            else
                result.EndpointSupportingTokenParameters.Endorsing.Add(issuedSecurityTokenParameters);

            SecurityBindingElement = result;
            return result;
        }

        public override BindingElementCollection CreateBindingElements()
        {
            var bindingElementCollection = base.CreateBindingElements();
            bindingElementCollection.Insert(0, new WsFederationBindingElement(IssuedTokenParameters, SecurityBindingElement));
            return bindingElementCollection;
        }

        public override IChannelFactory<TChannel> BuildChannelFactory<TChannel>(BindingParameterCollection parameters)
        {
            var channelFactory = base.BuildChannelFactory<TChannel>(parameters);
            return channelFactory;
        }

        protected override TransportBindingElement GetTransport()
        {
            var transportBindingElement = base.GetTransport();
            return transportBindingElement;
        }
    }
}
