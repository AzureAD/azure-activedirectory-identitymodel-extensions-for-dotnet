// Copyright (c) Microsoft Corporation. All rights reserved.
// Licensed under the MIT License.

using System;
using System.Collections.Generic;
using System.Collections.ObjectModel;
using Microsoft.IdentityModel.Logging;

namespace Microsoft.IdentityModel.Protocols.WsTrust
{
    /// <summary>
    /// Represents the contents of a Participants element.
    /// <see cref="Participants"/> can be used to represent entities that can share a security token.
    /// see: http://docs.oasis-open.org/ws-sx/ws-trust/200512/ws-trust-1.3-os.html
    /// </summary>
    public class Participants
    {
        private SecurityTokenElement _primary;

        /// <summary>
        /// Creates an instance of <see cref="Participants"/>.
        /// This constructor is useful when deserializing from a stream such as xml.
        /// Participants can be used to represent entities that can share a security token.
        /// </summary>
        public Participants()
        {
        }

        /// <summary>
        /// Creates an instance of <see cref="Participants"/>.
        /// Participants can be used to represent entities that can share a security token.
        /// </summary>
        /// <param name="primary">the primary participant of the security token.</param>
        /// <exception cref="ArgumentNullException">if <paramref name="primary"/> is null.</exception>
        public Participants(SecurityTokenElement primary)
        {
            Primary = primary;
        }

        /// <summary>
        /// Gets the Primary user of the Issued Token.
        /// </summary>
        /// <remarks>while no specific type is required, a security token or endpoint reference are common.</remarks>
        /// <exception cref="ArgumentNullException">if value is null.</exception>
        public SecurityTokenElement Primary
        {
            get => _primary;
            set => _primary = value ?? throw LogHelper.LogArgumentNullException(nameof(Primary));
        }

        /// <summary>
        /// Gets the collection of additional Participants.
        /// </summary>
        public ICollection<SecurityTokenElement> AdditionalParticipants { get; } = new Collection<SecurityTokenElement>();
    }
}
