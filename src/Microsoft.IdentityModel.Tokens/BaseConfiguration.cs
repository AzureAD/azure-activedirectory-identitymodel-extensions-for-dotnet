// Copyright (c) Microsoft Corporation. All rights reserved.
// Licensed under the MIT License.

using System.Collections.Generic;
using System.Collections.ObjectModel;

namespace Microsoft.IdentityModel.Tokens
{
    /// <summary>
    ///  Represents a generic metadata configuration which is applicable for both XML and JSON based configurations.
    /// </summary>
    public abstract class BaseConfiguration
    {
        /// <summary>
        /// Gets the issuer specified via the metadata endpoint.
        /// </summary>
        public virtual string Issuer { get; set; }

        /// <summary>
        /// Gets the <see cref="ICollection{SecurityKey}"/> that the IdentityProvider indicates are to be used in order to sign tokens.
        /// </summary>
        public virtual ICollection<SecurityKey> SigningKeys
        {
            get;
        } = new Collection<SecurityKey>();

        /// <summary>
        /// Gets or sets the token endpoint specified via the metadata endpoint.
        /// This can be the fed:SecurityTokenServiceType in WS-Federation, http://docs.oasis-open.org/wsfed/federation/v1.2/os/ws-federation-1.2-spec-os.html#:~:text=fed%3ASecurityTokenSerivceEndpoint
        /// Or the token_endpoint in the OIDC metadata.
        /// </summary>
        public virtual string TokenEndpoint { get; set; }
    }
}
