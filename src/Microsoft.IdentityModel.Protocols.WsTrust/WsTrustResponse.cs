// Copyright (c) Microsoft Corporation. All rights reserved.
// Licensed under the MIT License.

using System;
using System.Collections.Generic;
using Microsoft.IdentityModel.Logging;

namespace Microsoft.IdentityModel.Protocols.WsTrust
{
    /// <summary>
    /// Represents the contents of the RequestSecurityTokenCollection element.
    /// A WsTrustResponse is received from a STS in response to a WsTrust request..
    /// <para>see: http://docs.oasis-open.org/ws-sx/ws-trust/200512/ws-trust-1.3-os.html </para>
    /// <para><seealso cref="WsTrustSerializer"/> for serializing and de-serializing the response.</para>
    /// </summary>
    public class WsTrustResponse
    {
        internal WsTrustResponse()
        {
        }

        /// <summary>
        /// Instantiates a new <see cref="WsTrustResponse"/> with a <see cref="RequestSecurityTokenResponse"/>.
        /// </summary>
        /// <param name="requestSecurityTokenResponse">the response to add to the collection.</param>
        /// <exception cref="ArgumentNullException">thrown if <paramref name="requestSecurityTokenResponse"/> is null.</exception>
        public WsTrustResponse(RequestSecurityTokenResponse requestSecurityTokenResponse)
        {
            if (requestSecurityTokenResponse == null)
                throw LogHelper.LogArgumentNullException(nameof(requestSecurityTokenResponse));

            RequestSecurityTokenResponseCollection.Add(requestSecurityTokenResponse);
        }

        /// <summary>
        /// Gets the collection of <see cref="RequestSecurityTokenResponse"/>.
        /// </summary>
        public IList<RequestSecurityTokenResponse> RequestSecurityTokenResponseCollection { get; } = new List<RequestSecurityTokenResponse>();
    }
}
