// Copyright (c) Microsoft Corporation. All rights reserved.
// Licensed under the MIT License.

using System;
using Microsoft.IdentityModel.Logging;

namespace Microsoft.IdentityModel.Protocols.WsTrust
{
    /// <summary>
    /// Represents the contents of the Lifetime element.
    /// A Lifetime can be used to represent the creation and expiration times of a security token.
    /// <para>see: http://docs.oasis-open.org/ws-sx/ws-trust/200512/ws-trust-1.3-os.html </para>
    /// </summary>
    public class Lifetime
    {
        private DateTime? _created;
        private DateTime? _expires;

        /// <summary>
        /// Creates an instance of a <see cref="Lifetime"/>.
        /// <para>A Lifetime can be used to represent the creation and expiration times of a security token.</para>
        /// </summary>
        /// <param name="created">creation time, will be converted to UTC.</param>
        /// <param name="expires">expiration time will be converted to UTC.</param>
        /// <remarks>Value will be stored in UTC.</remarks>
        public Lifetime(DateTime created, DateTime expires)
            : this((DateTime?)created, (DateTime?)expires)
        {
        }

        /// <summary>
        /// Creates an instance of a <see cref="Lifetime"/>.
        /// A Lifetime can be used to represent the creation and expiration times of a security token.
        /// </summary>
        /// <param name="created">creation time, will be converted to UTC.</param>
        /// <param name="expires">expiration time will be converted to UTC.</param>
        /// <remarks>Value will be stored in UTC.</remarks>
        public Lifetime(DateTime? created, DateTime? expires)
        {
            if (created.HasValue && expires.HasValue && expires.Value <= created.Value)
                LogHelper.LogWarning(LogMessages.IDX15500);

            if (created.HasValue)
                Created = created.Value.ToUniversalTime();

            if (expires.HasValue)
                Expires = expires.Value.ToUniversalTime();
        }

        /// <summary>
        /// Gets or sets the creation time.
        /// </summary>
        /// <remarks>Value will be stored in UTC.</remarks>
        public DateTime? Created
        {
            get => _created;
            set => _created = (value.HasValue) ? _created = value.Value.ToUniversalTime() : value;
        }

        /// <summary>
        /// Gets or sets the expiration time.
        /// </summary>
        /// <remarks>Value will be stored in UTC.</remarks>
        public DateTime? Expires
        {
            get => _expires;
            set => _expires = (value.HasValue) ? _expires = value.Value.ToUniversalTime() : value;
        }
    }
}
