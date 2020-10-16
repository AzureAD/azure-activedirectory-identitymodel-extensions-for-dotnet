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
    public class Renewing
    {
        /// <summary>
        /// Constructs default <see cref="Renewing"/> element.
        /// </summary>
        public Renewing() {}

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
