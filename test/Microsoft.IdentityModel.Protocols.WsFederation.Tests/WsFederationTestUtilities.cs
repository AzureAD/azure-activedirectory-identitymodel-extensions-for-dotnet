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

using Microsoft.IdentityModel.Tests;
using Microsoft.IdentityModel.Tokens;
using Microsoft.IdentityModel.Tokens.Saml2;
using Microsoft.IdentityModel.Xml;

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
                    writer.WriteStartElement(WsTrustConstants_1_3.PreferredPrefix, WsTrustConstants.Elements.RequestSecurityTokenResponse, WsTrustConstants_1_3.Namespace);
                   
                    // <Lifetime>
                    writer.WriteStartElement(WsTrustConstants_1_3.PreferredPrefix, WsTrustConstants.Elements.Lifetime, WsTrustConstants.Namespaces.WsTrust1_3);

                    writer.WriteElementString(WsUtility.PreferredPrefix, WsUtility.Elements.Created, WsUtility.Namespace, Default.IssueInstantString);
                    writer.WriteElementString(WsUtility.PreferredPrefix, WsUtility.Elements.Expires, WsUtility.Namespace, Default.ExpiresString);

                    // </Lifetime>
                    writer.WriteEndElement();

                    // <AppliesTo>
                    writer.WriteStartElement(WsPolicy.PreferredPrefix, WsPolicy.Elements.AppliesTo, WsPolicy.Namespace);

                    // <EndpointReference>
                    writer.WriteStartElement(WsAddressing.PreferredPrefix, WsAddressing.Elements.EndpointReference, WsAddressing.Namespace);
                    writer.WriteElementString(WsAddressing.PreferredPrefix, WsAddressing.Elements.Address, WsAddressing.Namespace, Default.Audience);

                    // </EndpointReference>
                    writer.WriteEndElement();

                    // </AppliesTo>
                    writer.WriteEndElement();

                    // <RequestedSecurityToken>token</RequestedSecurityToken>
                    writer.WriteStartElement(WsTrustConstants_1_3.PreferredPrefix, WsTrustConstants.Elements.RequestedSecurityToken, WsTrustConstants_1_3.Namespace);

                    tokenHandler.WriteToken(writer, securityToken);

                    writer.WriteEndElement();

                    // <TokenType>tokenType</TokenType>
                    writer.WriteElementString(WsTrustConstants_1_3.PreferredPrefix, WsTrustConstants.Elements.TokenType, WsTrustConstants_1_3.Namespace, tokenType);

                    //<RequestType>http://schemas.xmlsoap.org/ws/2005/02/trust/Issue</RequestType>
                    writer.WriteElementString(WsTrustConstants_1_3.PreferredPrefix, WsTrustConstants.Elements.RequestType, WsTrustConstants_1_3.Namespace, WsTrustConstants_1_3.Actions.Issue);

                    //<KeyType>http://schemas.xmlsoap.org/ws/2005/05/identity/NoProofKey</KeyType>
                    writer.WriteElementString(WsTrustConstants_1_3.PreferredPrefix, WsTrustConstants.Elements.KeyType, WsTrustConstants_1_3.Namespace, "http://schemas.xmlsoap.org/ws/2005/05/identity/NoProofKey");

                    // </RequestSecurityTokenResponse>
                    writer.WriteEndElement();

                    writer.Flush();
                    var rstr = Encoding.UTF8.GetString(memoryStream.ToArray());

                    return "wa=wsignin1.0&wresult="+Uri.EscapeDataString(rstr);
                }
            }
        }
    }

}
