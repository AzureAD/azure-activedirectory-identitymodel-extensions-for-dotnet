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

using Microsoft.IdentityModel.Protocols.WsAddressing;
using Microsoft.IdentityModel.Protocols.WsFed;
using Microsoft.IdentityModel.Protocols.WsPolicy;
using Microsoft.IdentityModel.Protocols.WsSecurity;
using Microsoft.IdentityModel.Protocols.WsTrust;

namespace Microsoft.IdentityModel.Protocols
{
    /// <summary>
    /// Associates the usual protocol versions for a specific version of WsTrust.
    /// This is helpful when reading and writing WsTrust Requests and Responses.
    /// </summary>
    public class WsSerializationContext
    {
        /// <summary>
        /// Instantiates a <see cref="WsSerializationContext"/> that sets the expected versions of additional Ws* versions.
        /// </summary>
        /// <param name="wsTrustVersion">the <see cref="WsTrustVersion"/> to set the additional Ws* versions.</param>
        public WsSerializationContext(WsTrustVersion wsTrustVersion)
        {
            TrustVersion = wsTrustVersion;

            if (wsTrustVersion is WsTrustFeb2005Version)
            {
                AddressingConstants = WsAddressingConstants.Addressing10;
                FedConstants = WsFedConstants.Fed12;
                PolicyConstants = WsPolicyConstants.Policy12;
                SecurityConstants = WsSecurityConstants.WsSecurity10;
                TrustActions = WsTrustActions.TrustFeb2005;
                TrustConstants = WsTrustConstants.TrustFeb2005;
                TrustKeyTypes = WsTrustKeyTypes.TrustFeb2005;
            }
            else if (wsTrustVersion is WsTrust13Version)
            {
                AddressingConstants = WsAddressingConstants.Addressing10;
                FedConstants = WsFedConstants.Fed12;
                PolicyConstants = WsPolicyConstants.Policy12;
                SecurityConstants = WsSecurityConstants.WsSecurity11;
                TrustActions = WsTrustActions.Trust13;
                TrustConstants = WsTrustConstants.Trust13;
                TrustKeyTypes = WsTrustKeyTypes.Trust13;
            }
            else if (wsTrustVersion is WsTrust14Version)
            {
                AddressingConstants = WsAddressingConstants.Addressing10;
                FedConstants = WsFedConstants.Fed12;
                PolicyConstants = WsPolicyConstants.Policy12;
                SecurityConstants = WsSecurityConstants.WsSecurity11;
                TrustActions = WsTrustActions.Trust14;
                TrustConstants = WsTrustConstants.Trust14;
                TrustKeyTypes = WsTrustKeyTypes.Trust14;
            }
        }

        /// <summary>
        /// Gets the <see cref="WsAddressingConstants"/> associated with the <see cref="WsTrustVersion"/> passed to constructor.
        /// </summary>
        public WsAddressingConstants AddressingConstants { get; }

        /// <summary>
        /// Gets the <see cref="WsFedConstants"/> associated with the <see cref="WsTrustVersion"/> passed to constructor.
        /// </summary>
        public WsFedConstants FedConstants { get; }
       
        /// <summary>
        /// Gets the <see cref="WsPolicyConstants"/> associated with the <see cref="WsTrustVersion"/> passed to constructor.
        /// </summary>
        public WsPolicyConstants PolicyConstants { get; }

        /// <summary>
        /// Gets the <see cref="WsSecurityConstants"/> associated with the <see cref="WsTrustVersion"/> passed to constructor.
        /// </summary>
        public WsSecurityConstants SecurityConstants { get; }

        /// <summary>
        /// Gets the <see cref="WsTrustActions"/> associated with the <see cref="WsTrustVersion"/> passed to constructor.
        /// </summary>
        public WsTrustActions TrustActions { get; }

        /// <summary>
        /// Gets the <see cref="WsTrustConstants"/> associated with the <see cref="WsTrustVersion"/> passed to constructor.
        /// </summary>
        public WsTrustConstants TrustConstants { get; }

        /// <summary>
        /// Gets the <see cref="WsTrustKeyTypes"/> associated with the <see cref="WsTrustVersion"/> passed to constructor.
        /// </summary>
        public WsTrustKeyTypes TrustKeyTypes { get; }

        /// <summary>
        /// Gets the <see cref="WsTrustVersion"/> passed to constructor.
        /// </summary>
        public WsTrustVersion TrustVersion { get; }
    }
}
