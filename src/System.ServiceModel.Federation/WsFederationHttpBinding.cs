// Licensed to the .NET Foundation under one or more agreements.
// The .NET Foundation licenses this file to you under the MIT license.
// See the LICENSE file in the project root for more information.

#pragma warning disable 1591

using System.IdentityModel.Tokens;
using System.ServiceModel.Channels;

namespace System.ServiceModel.Federation
{
    public class WsFederationHttpBinding : WSHttpBinding
    {
        // binding is always TransportWithMessageCredentialy
        public WsFederationHttpBinding(WsTrustTokenParameters wsTrustTokenParameters) : base(SecurityMode.TransportWithMessageCredential)
        {
            WsTrustTokenParameters = wsTrustTokenParameters ?? throw new ArgumentNullException(nameof(wsTrustTokenParameters));
        }

        public WsTrustTokenParameters WsTrustTokenParameters
        {
            get;
        }

        private SecurityBindingElement SecurityBindingElement { get; set; }

        protected override SecurityBindingElement CreateMessageSecurity()
        {
            WsTrustTokenParameters.RequireDerivedKeys = false;
            var result = new TransportSecurityBindingElement
            {
                IncludeTimestamp = true,
            };

            if (WsTrustTokenParameters.KeyType == SecurityKeyType.BearerKey)
            {
                result.EndpointSupportingTokenParameters.Signed.Add(WsTrustTokenParameters);
                result.MessageSecurityVersion = WsTrustTokenParameters.MessageSecurityVersion;
            }
            else
            {
                result.EndpointSupportingTokenParameters.Endorsing.Add(WsTrustTokenParameters);
                result.MessageSecurityVersion = WsTrustTokenParameters.MessageSecurityVersion;
            }

            SecurityBindingElement = result;
            return result;
        }

        public override BindingElementCollection CreateBindingElements()
        {
            var bindingElementCollection = base.CreateBindingElements();
            bindingElementCollection.Insert(0, new WsFederationBindingElement(WsTrustTokenParameters, SecurityBindingElement));
            return bindingElementCollection;
        }


        protected override TransportBindingElement GetTransport()
        {
            var transportBindingElement = base.GetTransport();
            return transportBindingElement;
        }
    }
}
