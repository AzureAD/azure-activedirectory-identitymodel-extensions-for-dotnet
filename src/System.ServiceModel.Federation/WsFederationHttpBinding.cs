// Licensed to the .NET Foundation under one or more agreements.
// The .NET Foundation licenses this file to you under the MIT license.
// See the LICENSE file in the project root for more information.

#pragma warning disable 1591

using System.IdentityModel.Tokens;
using System.ServiceModel.Channels;
using System.ServiceModel.Security.Tokens;
using Microsoft.IdentityModel.Tokens;

namespace System.ServiceModel.Federation
{
    public class WsFederationHttpBinding : WSHttpBinding
    {
        // binding is always TransportWithMessageCredentialy
        public WsFederationHttpBinding(IssuedSecurityTokenParameters issuedTokenParameters) : base(SecurityMode.TransportWithMessageCredential)
        {
            IssuedSecurityTokenParameters = issuedTokenParameters ?? throw new ArgumentNullException(nameof(issuedTokenParameters));
        }

        public IssuedSecurityTokenParameters IssuedSecurityTokenParameters
        {
            get;
        }

        /// <summary>
        /// Gets or sets a context string used in outgoing WsTrust requests that may be useful for correlating requests.
        /// </summary>
        public string WSTrustContext
        {
            get;
            set;
        }

        private SecurityBindingElement SecurityBindingElement { get; set; }

        protected override SecurityBindingElement CreateMessageSecurity()
        {
            IssuedSecurityTokenParameters.RequireDerivedKeys = false;
            var result = new TransportSecurityBindingElement
            {
                IncludeTimestamp = true,
            };

            // TODO - result.MessageSecurityVersion is hard coded to work with current sample.
            if (IssuedSecurityTokenParameters.KeyType == SecurityKeyType.BearerKey)
            {
                result.EndpointSupportingTokenParameters.Signed.Add(IssuedSecurityTokenParameters);
                result.MessageSecurityVersion = MessageSecurityVersion.WSSecurity11WSTrust13WSSecureConversation13WSSecurityPolicy12BasicSecurityProfile10;
            }
            else
            {
                result.EndpointSupportingTokenParameters.Endorsing.Add(IssuedSecurityTokenParameters);
                result.MessageSecurityVersion = MessageSecurityVersion.WSSecurity11WSTrust13WSSecureConversation13WSSecurityPolicy12BasicSecurityProfile10;
            }

            SecurityBindingElement = result;
            return result;
        }

        public override BindingElementCollection CreateBindingElements()
        {
            var bindingElementCollection = base.CreateBindingElements();
            bindingElementCollection.Insert(0, new WsFederationBindingElement(IssuedSecurityTokenParameters, SecurityBindingElement) { WSTrustContext = WSTrustContext });
            return bindingElementCollection;
        }

        protected override TransportBindingElement GetTransport()
        {
            var transportBindingElement = base.GetTransport();
            return transportBindingElement;
        }
    }
}
