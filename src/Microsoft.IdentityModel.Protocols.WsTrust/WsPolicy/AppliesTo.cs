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
using Microsoft.IdentityModel.Logging;
using Microsoft.IdentityModel.Protocols.WsAddressing;

namespace Microsoft.IdentityModel.Protocols.WsPolicy
{
    /// <summary>
    /// Represents the contents of the AppliesTo element.
    /// This type is used when creating a WsTrust request to specify the relying party for the token.
    ///<para>Composes with <see cref="EndpointReference"/>.</para>
    /// <para>see: https://www.w3.org/Submission/2004/SUBM-ws-addressing-20040810/ </para>
    /// <para>see: http://docs.oasis-open.org/ws-sx/ws-trust/200512/ws-trust-1.3-os.html </para>
    /// </summary>
    public class AppliesTo
    {
        internal AppliesTo()
        {
        }

        /// <summary>
        /// Instantiates a <see cref="EndpointReference"/> specifying the relying party.
        /// </summary>
        /// <param name="endpointReference">the <see cref="EndpointReference"/> representing the relying party.</param>
        /// <exception cref="ArgumentNullException">thrown if <paramref name="endpointReference"/> is null.</exception>
        public AppliesTo(EndpointReference endpointReference)
        {
            EndpointReference = endpointReference ?? throw LogHelper.LogArgumentNullException(nameof(endpointReference));
        }

        /// <summary>
        /// Gets the <see cref="EndpointReference"/> that was passed in the constructor.
        /// </summary>
        public EndpointReference EndpointReference { get; }
    }
}
