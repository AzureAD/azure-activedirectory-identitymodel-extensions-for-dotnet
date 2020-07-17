//------------------------------------------------------------------------------
//
// Copyright (c) Microsoft Corporation.
// All rights reserved.
//
// This code is licensed under the MIT License.
//
// Permission is hereby granted, free of charge, to any person obtaining a copy
// of this software and associated documentation files(the "Software"), to deal
// in the Software without restriction, including without limitation the rights
// to use, copy, modify, merge, publish, distribute, sublicense, and / or sell
// copies of the Software, and to permit persons to whom the Software is
// furnished to do so, subject to the following conditions :
//
// The above copyright notice and this permission notice shall be included in
// all copies or substantial portions of the Software.
//
// THE SOFTWARE IS PROVIDED "AS IS", WITHOUT WARRANTY OF ANY KIND, EXPRESS OR
// IMPLIED, INCLUDING BUT NOT LIMITED TO THE WARRANTIES OF MERCHANTABILITY,
// FITNESS FOR A PARTICULAR PURPOSE AND NONINFRINGEMENT.IN NO EVENT SHALL THE
// AUTHORS OR COPYRIGHT HOLDERS BE LIABLE FOR ANY CLAIM, DAMAGES OR OTHER
// LIABILITY, WHETHER IN AN ACTION OF CONTRACT, TORT OR OTHERWISE, ARISING FROM,
// OUT OF OR IN CONNECTION WITH THE SOFTWARE OR THE USE OR OTHER DEALINGS IN
// THE SOFTWARE.
//
//------------------------------------------------------------------------------

using System;
using System.Diagnostics.CodeAnalysis;
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
        /// Creates an instance of <see cref="Lifetime"/>.
        /// <para>>A Lifetime can be used to represent the creation and expiration times of a security token.</para>
        /// </summary>
        public Lifetime()
        {
        }

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
