// Copyright (c) Microsoft Corporation. All rights reserved.
// Licensed under the MIT License.

using System;
using Microsoft.IdentityModel.Logging;

namespace Microsoft.IdentityModel.Protocols.WsTrust
{
    /// <summary>
    /// Represents the contents of the RequestSecurityToken element.
    /// A WsTrustRequest can be serialized into a WsTrust request and sent to a token service to obtain a security token.
    /// <para>see: http://docs.oasis-open.org/ws-sx/ws-trust/200512/ws-trust-1.3-os.html </para>
    /// <para><seealso cref="WsTrustSerializer"/> for serializing and de-serializing the request.</para>
    /// </summary>
    public class WsTrustRequest : WsTrustMessage
    {
        private string _requestType;

        /// <summary>
        /// Creates an instance of <see cref="WsTrustRequest"/>.
        /// <paramref name="requestType">the type of this request.</paramref>
        /// </summary>
        /// <exception cref="ArgumentNullException">Thrown if <paramref name="requestType"/> is null or empty.</exception>
        public WsTrustRequest(string requestType)
        {
            RequestType = requestType;
        }

        /// <summary>
        /// Gets or sets if the token requested can be postdated.
        /// </summary>
        public bool? AllowPostdating { get; set; }

        /// <summary>
        /// Gets the request type.
        /// </summary>
        /// <exception cref="ArgumentNullException">Thrown if RequestType is null or empty.</exception>
        public string RequestType
        {
            get => _requestType;
            internal set => _requestType = string.IsNullOrEmpty(value) ? throw LogHelper.LogArgumentNullException(nameof(RequestType)) : value;
        }
    }
}
