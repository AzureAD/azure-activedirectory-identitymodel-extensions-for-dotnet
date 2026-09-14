// Copyright (c) Microsoft Corporation. All rights reserved.
// Licensed under the MIT License.

namespace Microsoft.IdentityModel.Protocols
{
    /// <summary>
    /// Base class for all Ws* constants.
    /// Ensures each type has defined a Namespace and Prefix
    /// </summary>
    public abstract class WsConstantsBase
    {
        /// <summary>
        /// Gets the namespace for a protocol version.
        /// </summary>
        public string Namespace { get; protected set; }

        /// <summary>
        /// Gets the preferred prefix for a protocol version.
        /// </summary>
        public string Prefix { get; protected set; }
    }
}
