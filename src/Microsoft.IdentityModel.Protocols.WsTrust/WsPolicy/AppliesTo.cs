// Copyright (c) Microsoft Corporation. All rights reserved.
// Licensed under the MIT License.

using System;
using Microsoft.IdentityModel.Logging;
using Microsoft.IdentityModel.Protocols.WsAddressing;

namespace Microsoft.IdentityModel.Protocols.WsPolicy
{
    /// <summary>
    /// Represents the contents of the AppliesTo element.
    /// This type is used when creating a WsTrust request to specify the relying party for the token.
    ///<para>Composes with <see cref="EndpointReference"/>.</para>
    /// <para>see: https://www.w3.org/Submission/2004/SUBM-ws-addressing-20040810/ </para>
    /// <para>see: http://docs.oasis-open.org/ws-sx/ws-trust/200512/ws-trust-1.3-os.html </para>
    /// </summary>
    public class AppliesTo
    {
        internal AppliesTo()
        {
        }

        /// <summary>
        /// Instantiates a <see cref="EndpointReference"/> specifying the relying party.
        /// </summary>
        /// <param name="endpointReference">the <see cref="EndpointReference"/> representing the relying party.</param>
        /// <exception cref="ArgumentNullException">thrown if <paramref name="endpointReference"/> is null.</exception>
        public AppliesTo(EndpointReference endpointReference)
        {
            EndpointReference = endpointReference ?? throw LogHelper.LogArgumentNullException(nameof(endpointReference));
        }

        /// <summary>
        /// Gets the <see cref="EndpointReference"/> that was passed in the constructor.
        /// </summary>
        public EndpointReference EndpointReference { get; }
    }
}
