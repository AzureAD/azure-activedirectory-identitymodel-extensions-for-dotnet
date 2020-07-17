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

using System.IO;
using System.Text;
using System.Xml;
using Microsoft.IdentityModel.Protocols.WsSecurity;
using Microsoft.IdentityModel.TestUtils;
using Microsoft.IdentityModel.Tokens;

#pragma warning disable CS3016 // Arrays as attribute arguments is not CLS-compliant

namespace Microsoft.IdentityModel.Protocols.WsTrust.Tests
{
    public class WsTrustTheoryData : TheoryDataBase
    {
        public WsTrustTheoryData() { }

        public WsTrustTheoryData(WsTrustVersion trustVersion)
        {
            WsSerializationContext = new WsSerializationContext(trustVersion);
            WsTrustVersion = trustVersion;
        }

        public WsTrustTheoryData(XmlDictionaryReader reader)
        {
            Reader = reader;
        }

        public WsTrustTheoryData(MemoryStream memoryStream)
        {
            MemoryStream = memoryStream;
            Writer = XmlDictionaryWriter.CreateTextWriter(memoryStream, Encoding.UTF8);
        }

        public WsTrustTheoryData(MemoryStream memoryStream, WsTrustVersion trustVersion)
        {
            MemoryStream = memoryStream;
            Writer = XmlDictionaryWriter.CreateTextWriter(memoryStream, Encoding.UTF8);
            WsSerializationContext = new WsSerializationContext(trustVersion);
            WsTrustVersion = trustVersion;
        }

        public BinarySecret BinarySecret { get; set; }

        public Claims Claims { get; set; }

        public Entropy Entropy { get; set; }

        public Lifetime Lifetime { get; set; }

        public MemoryStream MemoryStream { get; set; }

        public SecurityTokenElement OnBehalfOf { get; set; }

        public SecurityTokenElement ProofEncryption { get; set; }

        public XmlDictionaryReader Reader { get; set; }

        public SecurityTokenReference Reference { get; set; }

        public SecurityTokenReference RequestedAttachedReference { get; set; }

        public RequestedProofToken RequestedProofToken { get; set; }

        public RequestedSecurityToken RequestedSecurityToken { get; set; }

        public SecurityTokenReference RequestedUnattachedReference { get; set; }

        public RequestSecurityTokenResponse RequestSecurityTokenResponse { get; set; }

        public SecurityTokenHandler SecurityTokenHandler { get; set; }

        public TokenValidationParameters TokenValidationParameters { get; set; }

        public UseKey UseKey { get; set; }

        public XmlDictionaryWriter Writer { get; set; }

        public WsSerializationContext WsSerializationContext { get; set; }

        public WsTrustRequest WsTrustRequest { get; set; }

        public WsTrustResponse WsTrustResponse { get; set; }

        public WsTrustSerializer WsTrustSerializer { get; set; } = new WsTrustSerializer();

        public WsTrustVersion WsTrustVersion { get; set; }
    }
}
