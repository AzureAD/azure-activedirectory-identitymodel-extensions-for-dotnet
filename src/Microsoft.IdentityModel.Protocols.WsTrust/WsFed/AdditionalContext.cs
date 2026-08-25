// Copyright (c) Microsoft Corporation. All rights reserved.
// Licensed under the MIT License.

using System;
using System.Collections.Generic;
using Microsoft.IdentityModel.Logging;

namespace Microsoft.IdentityModel.Protocols.WsFed
{
    /// <summary>
    /// Represents the contents of the AdditionalContext element used to convey desired properties of the token.
    /// <para>see: http://docs.oasis-open.org/wsfed/federation/v1.2/os/ws-federation-1.2-spec-os.html </para>
    /// </summary>
    public class AdditionalContext
    {
        /// <summary>
        /// Creates an instance of <see cref="AdditionalContext"/>.
        /// <para>AdditionalContext element used to convey desired properties of the token.</para>
        /// </summary>
        public AdditionalContext()
        {
            Items = new List<ContextItem>();
        }

        /// <summary>
        /// Initializes an instance of <see cref="AdditionalContext"/>
        /// </summary>
        /// <param name="items">Collection of <see cref="ContextItem"/>.</param>
        /// <exception cref="ArgumentNullException"> <paramref name="items"/> is null.</exception>
        public AdditionalContext(IList<ContextItem> items)
        {
            Items = items ?? throw LogHelper.LogArgumentNullException(nameof(items));
        }

        /// <summary>
        /// Gets the List of <see cref="ContextItem"/>.
        /// </summary>
        public IList<ContextItem> Items
        {
            get;
        }
    }
}
