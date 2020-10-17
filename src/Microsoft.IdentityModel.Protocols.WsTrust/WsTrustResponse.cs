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
using Microsoft.IdentityModel.Logging;

namespace Microsoft.IdentityModel.Protocols.WsTrust
{
    /// <summary>
    /// Represents the contents of the RequestSecurityTokenCollection element.
    /// A WsTrustResponse is received from a STS in response to a WsTrust request..
    /// <para>see: http://docs.oasis-open.org/ws-sx/ws-trust/200512/ws-trust-1.3-os.html </para>
    /// <para><seealso cref="WsTrustSerializer"/> for serializing and de-serializing the response.</para>
    /// </summary>
    public class WsTrustResponse
    {
        internal WsTrustResponse()
        {
        }

        /// <summary>
        /// Instantiates a new <see cref="WsTrustResponse"/> with a <see cref="RequestSecurityTokenResponse"/>.
        /// </summary>
        /// <param name="requestSecurityTokenResponse">the response to add to the collection.</param>
        /// <exception cref="ArgumentNullException">thrown if <paramref name="requestSecurityTokenResponse"/> is null.</exception>
        public WsTrustResponse(RequestSecurityTokenResponse requestSecurityTokenResponse)
        {
            if (requestSecurityTokenResponse == null)
                LogHelper.LogArgumentNullException(nameof(requestSecurityTokenResponse));

            RequestSecurityTokenResponseCollection.Add(requestSecurityTokenResponse);
        }

        /// <summary>
        /// Gets the collection of <see cref="RequestSecurityTokenResponse"/>.
        /// </summary>
        public IList<RequestSecurityTokenResponse> RequestSecurityTokenResponseCollection { get; } = new List<RequestSecurityTokenResponse>();
    }
}
