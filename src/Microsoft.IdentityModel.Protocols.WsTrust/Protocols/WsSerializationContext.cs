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

using Microsoft.IdentityModel.Protocols.WsAddressing;
using Microsoft.IdentityModel.Protocols.WsFed;
using Microsoft.IdentityModel.Protocols.WsPolicy;
using Microsoft.IdentityModel.Protocols.WsSecurity;
using Microsoft.IdentityModel.Protocols.WsTrust;

namespace Microsoft.IdentityModel.Protocols
{
    /// <summary>
    /// Used to remember the prefix, namespace to use / expect when reading and writing WsTrust Requests and Responses.
    /// </summary>
    public class WsSerializationContext
    {
        public WsSerializationContext(WsTrustVersion wsTrustVersion, WsAddressingVersion wsAddressingVersion, WsSecurityVersion wsSecurityVersion)
        {
            TrustVersion = wsTrustVersion;

            FedConstants = WsFedConstants.Fed12;
            PolicyConstants = WsPolicyConstants.Policy12;

            if (wsAddressingVersion is WsAddressing10Version)
                AddressingConstants = WsAddressingConstants.Addressing10;
            else
                AddressingConstants = WsAddressingConstants.Addressing200408;

            if (wsSecurityVersion is WsSecurity10Version)
                SecurityConstants = WsSecurityConstants.WsSecurity10;
            else
                SecurityConstants = WsSecurityConstants.WsSecurity11;

            if (wsTrustVersion is WsTrustFeb2005Version)
            {
                TrustActions = WsTrustActions.TrustFeb2005;
                TrustConstants = WsTrustConstants.TrustFeb2005;
                TrustKeyTypes = WsTrustKeyTypes.TrustFeb2005;
            }
            else if (wsTrustVersion is WsTrust13Version)
            {
                TrustActions = WsTrustActions.Trust13;
                TrustConstants = WsTrustConstants.Trust13;
                TrustKeyTypes = WsTrustKeyTypes.Trust13;
            }
            else if (wsTrustVersion is WsTrust14Version)
            {
                TrustActions = WsTrustActions.Trust14;
                TrustConstants = WsTrustConstants.Trust14;
                TrustKeyTypes = WsTrustKeyTypes.Trust14;
            }
        }

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

        public WsAddressingConstants AddressingConstants { get; }

        public WsFedConstants FedConstants { get; }
       
        public WsPolicyConstants PolicyConstants { get; }

        public WsSecurityConstants SecurityConstants { get; }

        public WsTrustActions TrustActions { get; }

        public WsTrustConstants TrustConstants { get; }

        public WsTrustKeyTypes TrustKeyTypes { get; }

        public WsTrustVersion TrustVersion { get; }
    }
}
