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
using Microsoft.IdentityModel.Protocols.WsSecurity;

namespace Microsoft.IdentityModel.Protocols.WsTrust
{
    /// <summary>
    /// Represents the contents of a RequestSecurityTokenResponse element.
    /// <see cref="RequestSecurityTokenResponse"/> represents the results of a security token request sent to a security token provider.
    /// see: http://docs.oasis-open.org/ws-sx/ws-trust/200512/ws-trust-1.3-os.html
    /// </summary>
    public class RequestSecurityTokenResponse : WsTrustMessage
    {
        private SecurityTokenReference _attachedReference;
        private RequestedProofToken _requestedProofToken;
        private RequestedSecurityToken _securityToken;
        private SecurityTokenReference _unattachedReference;

        /// <summary>
        /// Creates an instance of <see cref="RequestSecurityTokenResponse"/>.
        /// </summary>
        public RequestSecurityTokenResponse()
        {
        }

        /// <summary>
        /// Gets or sets the AttachedReference
        /// </summary>
        /// <exception cref="ArgumentNullException">if AttachedReference is null.</exception>
        public SecurityTokenReference AttachedReference
        {
            get => _attachedReference;
            set => _attachedReference = value ?? throw LogHelper.LogArgumentNullException(nameof(AttachedReference));
        }

        /// <summary>
        /// Gets or sets the <see cref="RequestedProofToken"/>.
        /// </summary>
        /// <exception cref="ArgumentNullException">if RequestedSecurityToken is null.</exception>
        public RequestedProofToken RequestedProofToken
        {
            get => _requestedProofToken;
            set => _requestedProofToken = value ?? throw LogHelper.LogArgumentNullException(nameof(RequestedProofToken));
        }

        /// <summary>
        /// Gets or sets the <see cref="RequestedSecurityToken"/>.
        /// </summary>
        /// <exception cref="ArgumentNullException">if RequestedSecurityToken is null.</exception>
        public RequestedSecurityToken RequestedSecurityToken
        {
            get => _securityToken;
            set => _securityToken = value ?? throw LogHelper.LogArgumentNullException(nameof(RequestedSecurityToken));
        }

        /// <summary>
        /// Gets or sets the UnattachedReference
        /// </summary>
        /// <exception cref="ArgumentNullException">if UnattachedReference is null.</exception>
        public SecurityTokenReference UnattachedReference
        {
            get => _unattachedReference;
            set => _unattachedReference = value ?? throw LogHelper.LogArgumentNullException(nameof(UnattachedReference));
        }
    }
}
