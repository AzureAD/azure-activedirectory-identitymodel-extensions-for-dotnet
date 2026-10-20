// Copyright (c) Microsoft Corporation. All rights reserved.
// Licensed under the MIT License.

using System.ComponentModel;

namespace Microsoft.IdentityModel.Protocols.WsTrust
{
    /// <summary>
    /// Represents the contents of a Renewing element in a RequestSecurityToken message.
    /// see: http://docs.oasis-open.org/ws-sx/ws-trust/200512/ws-trust-1.3-os.html
    /// </summary>
    /// <remarks>
    /// The Renewing element is used to indicate a preference if token can be renewed
    /// or renewed after expiration.
    /// </remarks>
    internal class Renewing
    {
        /// <summary>
        /// Constructs default <see cref="Renewing"/> element.
        /// </summary>
        public Renewing() { }

        /// <summary>
        /// Gets or sets if a token should allow requests for renewal.
        /// </summary>
        [DefaultValue(true)]
        public bool Allow { get; set; } = true;

        /// <summary>
        /// Gets of sets if a token can be renewed after expiration.
        /// </summary>
        [DefaultValue(false)]
        public bool RenewAfterExpiration { get; set; } = false;
    }
}
