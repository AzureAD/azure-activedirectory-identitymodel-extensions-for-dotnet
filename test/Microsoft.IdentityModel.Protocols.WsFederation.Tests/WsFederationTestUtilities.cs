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
using System.IO;
using System.Text;
using System.Xml;
using Microsoft.IdentityModel.TestUtils;
using Microsoft.IdentityModel.Tokens;
using Microsoft.IdentityModel.Protocols.WsAddressing;
using Microsoft.IdentityModel.Protocols.WsTrust;
using Microsoft.IdentityModel.Protocols.WsUtility;
using Microsoft.IdentityModel.Protocols.WsPolicy;

namespace Microsoft.IdentityModel.Protocols.WsFederation.Tests
{
    public static class WsFederationTestUtilities
    {
        public static string BuildWaSignInMessage(SecurityToken securityToken, SecurityTokenHandler tokenHandler, string tokenType )
        {
            using (var memoryStream = new MemoryStream())
            {
                using (var writer = XmlDictionaryWriter.CreateTextWriter(memoryStream, Encoding.UTF8, false))
                {
                    // <RequestSecurityTokenResponse>
                    writer.WriteStartElement(WsTrustConstants.Trust13.Prefix, WsTrustElements.RequestSecurityTokenResponse, WsTrustConstants.Trust13.Namespace);
                   
                    // <Lifetime>
                    writer.WriteStartElement(WsTrustConstants.Trust13.Prefix, WsTrustElements.Lifetime, WsTrustConstants.Trust13.Namespace);

                    writer.WriteElementString(WsUtilityConstants.WsUtility10.Prefix, WsUtilityElements.Created, WsUtilityConstants.WsUtility10.Namespace, Default.IssueInstantString);
                    writer.WriteElementString(WsUtilityConstants.WsUtility10.Prefix, WsUtilityElements.Expires, WsUtilityConstants.WsUtility10.Namespace, Default.ExpiresString);

                    // </Lifetime>
                    writer.WriteEndElement();

                    // <AppliesTo>
                    writer.WriteStartElement(WsPolicyConstants.Policy12.Prefix, WsPolicyElements.AppliesTo, WsPolicyConstants.Policy12.Namespace);

                    // <EndpointReference>
                    writer.WriteStartElement(WsAddressingConstants.Addressing10.Prefix, WsAddressingElements.EndpointReference, WsAddressingConstants.Addressing10.Namespace);
                    writer.WriteElementString(WsAddressingConstants.Addressing10.Prefix, WsAddressingElements.Address, WsAddressingConstants.Addressing10.Namespace, Default.Audience);

                    // </EndpointReference>
                    writer.WriteEndElement();

                    // </AppliesTo>
                    writer.WriteEndElement();

                    // <RequestedSecurityToken>token</RequestedSecurityToken>
                    writer.WriteStartElement(WsTrustConstants.Trust13.Prefix, WsTrustElements.RequestedSecurityToken, WsTrustConstants.Trust13.Namespace);

                    tokenHandler.WriteToken(writer, securityToken);

                    writer.WriteEndElement();

                    // <TokenType>tokenType</TokenType>
                    writer.WriteElementString(WsTrustConstants.Trust13.Prefix, WsTrustElements.TokenType, WsTrustConstants.Trust13.Namespace, tokenType);

                    //<RequestType>http://schemas.xmlsoap.org/ws/2005/02/trust/Issue</RequestType>
                    writer.WriteElementString(WsTrustConstants.Trust13.Prefix, WsTrustElements.RequestType, WsTrustConstants.Trust13.Namespace, WsTrustActions.Trust13.Issue);

                    //<KeyType>http://schemas.xmlsoap.org/ws/2005/05/identity/NoProofKey</KeyType>
                    writer.WriteElementString(WsTrustConstants.Trust13.Prefix, WsTrustElements.KeyType, WsTrustConstants.Trust13.Namespace, "http://schemas.xmlsoap.org/ws/2005/05/identity/NoProofKey");

                    // </RequestSecurityTokenResponse>
                    writer.WriteEndElement();

                    writer.Flush();
                    var rstr = Encoding.UTF8.GetString(memoryStream.ToArray());

                    return "wa=wsignin1.0&wresult="+Uri.EscapeDataString(rstr);
                }
            }
        }

        public static string BuildWaSignInMessage(string securityToken, string tokenType)
        {
            var rstrTemplate = @"<t:RequestSecurityTokenResponse xmlns:t=""http://docs.oasis-open.org/ws-sx/ws-trust/200512""><t:Lifetime><wsu:Created xmlns:wsu=""http://www.w3.org/2005/08/addressing"">2017-03-17T18:33:37.095Z</wsu:Created><wsu:Expires xmlns:wsu=""http://www.w3.org/2005/08/addressing"">2021-03-17T18:33:37.080Z</wsu:Expires></t:Lifetime><wsp:AppliesTo xmlns:wsp=""http://schemas.xmlsoap.org/ws/2004/09/policy""><wsa:EndpointReference xmlns:wsa=""http://www.w3.org/2005/08/addressing""><wsa:Address>http://Default.Audience.com</wsa:Address></wsa:EndpointReference></wsp:AppliesTo><t:RequestedSecurityToken>{0}</t:RequestedSecurityToken><t:TokenType>{1}</t:TokenType><t:RequestType>http://docs.oasis-open.org/ws-sx/ws-trust/200512/RST/Issue</t:RequestType><t:KeyType>http://schemas.xmlsoap.org/ws/2005/05/identity/NoProofKey</t:KeyType></t:RequestSecurityTokenResponse>";
            var rstr = string.Format(rstrTemplate, securityToken, tokenType);

            return "wa=wsignin1.0&wresult=" + Uri.EscapeDataString(rstr);
        }
    }
}
