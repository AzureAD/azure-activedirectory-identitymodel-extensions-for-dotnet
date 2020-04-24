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

#pragma warning disable 1591

using System;
using Microsoft.IdentityModel.Logging;

namespace Microsoft.IdentityModel.Protocols.WsTrust
{
    /// <summary>
    /// Represents the contents of the RequestSecurityToken element.
    /// A WsTrustRequest can be serialized into a WsTrust request and sent to a token service to obtain a security token.
    /// <para>see: http://docs.oasis-open.org/ws-sx/ws-trust/200512/ws-trust-1.3-os.html </para>
    /// <para><seealso cref="WsTrustSerializer"/> for serializing and de-serializing the request.</para>
    /// </summary>
    public class WsTrustRequest : WsTrustMessage
    {
        private string _requestType;

        /// <summary>
        /// Creates an instance of <see cref="WsTrustRequest"/>.
        /// <paramref name="requestType">the type of this request.</paramref>
        /// </summary>
        /// <exception cref="ArgumentNullException">Thrown if <paramref name="requestType"/> is null or empty.</exception>
        public WsTrustRequest(string requestType)
        {
            RequestType = requestType;
        }

        /// <summary>
        /// Gets or sets if the token requested can be postdated.
        /// </summary>
        public bool? AllowPostdating { get; set; }

        /// <summary>
        /// Gets the request type.
        /// </summary>
        /// <exception cref="ArgumentNullException">Thrown if RequestType is null or empty.</exception>
        public string RequestType
        {
            get => _requestType;
            internal set => _requestType = string.IsNullOrEmpty(value) ? throw LogHelper.LogArgumentNullException(nameof(RequestType)) : value;
        }
    }
}
