// Copyright (c) Microsoft Corporation. All rights reserved.
// Licensed under the MIT License.

using System;
using Microsoft.IdentityModel.Logging;
using Microsoft.IdentityModel.Protocols.WsSecurity;
using Microsoft.IdentityModel.Tokens;

namespace Microsoft.IdentityModel.Protocols.WsTrust
{
    /// <summary>
    /// Represents the contents of a UseKey element.
    /// <para>
    /// <see cref="UseKey"/> can be used to specify an existing key to use with a WStrust request.
    /// </para>
    /// see: http://docs.oasis-open.org/ws-sx/ws-trust/200512/ws-trust-1.3-os.html
    /// </summary>
    public class UseKey
    {
        private string _signatureId;

        /// <summary>
        /// Creates an instance of <see cref="UseKey"/>.
        /// </summary>
        /// <param name="securityTokenElement">A <see cref="SecurityTokenElement"/> that contains key material that will be sent to the token issuer that can be set as the proof key inside the token returned.</param>
        /// <exception cref="ArgumentNullException">Thrown if <paramref name="securityTokenElement"/> is null.</exception>
        public UseKey(SecurityTokenElement securityTokenElement)
        {
            SecurityTokenElement = securityTokenElement ?? throw LogHelper.LogArgumentNullException(nameof(securityTokenElement));
        }

        /// <summary>
        /// Gets the <see cref="SecurityTokenElement"/> passed to the constructor.
        /// </summary>
        public SecurityTokenElement SecurityTokenElement
        {
            get;
        }

        /// <summary>
        /// Gets or sets the SignatureId that identifies a element in a signed envelope that shows proof of using the <see cref="SecurityTokenReference"/> or <see cref="SecurityToken"/>.
        /// </summary>
        /// <exception cref="ArgumentNullException">Thrown if SignatureId is null or empty.</exception>
        public string SignatureId
        {
            get => _signatureId;
            set => _signatureId = string.IsNullOrEmpty(value) ? throw LogHelper.LogArgumentNullException(nameof(SignatureId)) : value;
        }
    }
}
