// Copyright (c) Microsoft Corporation. All rights reserved.
// Licensed under the MIT License.

using System;
using System.Xml;
using Microsoft.IdentityModel.Logging;
using Microsoft.IdentityModel.Tokens;

namespace Microsoft.IdentityModel.Protocols.WsTrust
{
    /// <summary>
    /// Represents the contents of a RequestedSecurityToken element.
    /// <see cref="RequestedSecurityToken"/> represents the security token returned in a WsTrust response.
    /// see: http://docs.oasis-open.org/ws-sx/ws-trust/200512/ws-trust-1.3-os.html
    /// </summary>
    public class RequestedSecurityToken
    {
        private SecurityToken _securityToken;
        private XmlElement _xmlElement;

        /// <summary>
        /// Creates an instance of <see cref="RequestedSecurityToken"/>.
        /// This constructor is useful when deserializing from a stream such as xml.
        /// </summary>
        internal RequestedSecurityToken()
        {
        }

        /// <summary>
        /// Instantiates an instance of <see cref="RequestedSecurityToken"/> with a specific <see cref="XmlElement"/>.
        /// </summary>
        /// <param name="xmlElement">an <see cref="XmlElement"/> of the callers choice.</param>
        /// <exception cref="ArgumentNullException">thrown if <paramref name="xmlElement"/> is null.</exception>
        public RequestedSecurityToken(XmlElement xmlElement)
        {
            _xmlElement = xmlElement ?? throw LogHelper.LogArgumentNullException(nameof(xmlElement));
        }

        /// <summary>
        /// Creates an instance of <see cref="RequestedSecurityToken"/>.
        /// </summary>
        /// <param name="securityToken">a <see cref="SecurityToken"/>.</param>
        /// <exception cref="ArgumentNullException">thrown if <paramref name="securityToken"/> is null.</exception>
        public RequestedSecurityToken(SecurityToken securityToken)
        {
            SecurityToken = securityToken ?? throw LogHelper.LogArgumentNullException(nameof(securityToken));
        }

        /// <summary>
        /// Gets or sets the token.
        /// </summary>
        /// <exception cref="ArgumentNullException">if TokenElement is null.</exception>
        public XmlElement TokenElement
        {
            get => _xmlElement;
            set => _xmlElement = value ?? throw LogHelper.LogArgumentNullException(nameof(TokenElement));
        }


        /// <summary>
        /// Gets or set the <see cref="SecurityToken"/>.
        /// </summary>
        /// <exception cref="ArgumentNullException">if SecurityToken is null.</exception>
        public SecurityToken SecurityToken
        {
            get => _securityToken;
            set => _securityToken = value ?? throw LogHelper.LogArgumentNullException(nameof(SecurityToken));
        }
    }
}
