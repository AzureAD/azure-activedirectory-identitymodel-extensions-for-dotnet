// Copyright (c) Microsoft Corporation. All rights reserved.
// Licensed under the MIT License.

using System;
using System.Collections.Generic;
using Microsoft.IdentityModel.Logging;
using Microsoft.IdentityModel.Protocols.WsFed;

namespace Microsoft.IdentityModel.Protocols.WsTrust
{
    /// <summary>
    /// Represents the contents of the Claims element.
    /// The Claims element contains specific claims that are being requested.
    /// see: http://docs.oasis-open.org/ws-sx/ws-trust/200512/ws-trust-1.3-os.html
    /// </summary>
    public class Claims
    {
        /// <summary>
        /// Creates an instance of <see cref="Claims"/>
        /// </summary>
        /// <param name="dialect">a uri that defines the dialect of the claims.</param>
        /// <param name="claimTypes">a list of <see cref="ClaimType"/>.</param>
        /// <exception cref="ArgumentNullException">thrown if <paramref name="dialect"/> is null or empty</exception>
        /// <exception cref="ArgumentNullException">thrown if <paramref name="claimTypes"/> is null.</exception>
        public Claims(string dialect, IList<ClaimType> claimTypes)
        {
            Dialect = string.IsNullOrEmpty(dialect) ? throw LogHelper.LogArgumentNullException(nameof(dialect)) : dialect;
            ClaimTypes = claimTypes ?? throw LogHelper.LogArgumentNullException(nameof(claimTypes));
        }

        /// <summary>
        /// Gets the list of <see cref="ClaimType"/>.
        /// </summary>
        public IList<ClaimType> ClaimTypes { get; }

        /// <summary>
        /// Gets the dialect of these claims.
        /// </summary>
        public string Dialect { get; }
    }
}
