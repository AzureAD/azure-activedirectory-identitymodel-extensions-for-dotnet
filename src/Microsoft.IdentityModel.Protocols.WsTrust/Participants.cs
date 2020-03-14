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
        /// Gets the colllection of additional Participants.
        /// </summary>
        public ICollection<SecurityTokenElement> AdditionalParticipants { get; } = new Collection<SecurityTokenElement>();
    }
}
