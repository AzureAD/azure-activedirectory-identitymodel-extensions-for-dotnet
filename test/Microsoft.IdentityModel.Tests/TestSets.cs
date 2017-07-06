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

using Microsoft.IdentityModel.Protocols.WsFederation;
using Microsoft.IdentityModel.Tokens;
using Microsoft.IdentityModel.Tokens.Saml;
using Microsoft.IdentityModel.Xml;

namespace Microsoft.IdentityModel.Tests
{
#region Saml
    public class SamlActionTestSet
    {
        public string Xml { get; set; }
        public SamlAction Action { get; set; }
    }

    public class SamlAudienceRestrictionConditionTestSet
    {
        public string Xml { get; set; }
        public SamlAudienceRestrictionCondition AudienceRestrictionCondition { get; set; }
    }

    public class SamlAttributeTestSet
    {
        public string Xml { get; set; }
        public SamlAttribute Attribute { get; set; }
    }

    public class SamlConditionsTestSet
    {
        public string Xml { get; set; }
        public SamlConditions Conditions { get; set; }
    }
#endregion

    public class KeyInfoTestSet
    {
        public string Xml { get; set; }

        public KeyInfo KeyInfo { get; set; }
    }

    public class SamlSecurityTokenTestSet
    {
        public SamlSecurityToken SamlSecurityToken { get; set; }
        public string Xml { get; set; }
    }

    public class SignatureTestSet
    {
        public SecurityKey SecurityKey { get; set; } = ReferenceXml.DefaultAADSigningKey;

        public Signature Signature { get; set; }

        public string Xml { get; set; }
    }

    public class SignedInfoTestSet
    {
        public SignedInfo SignedInfo { get; set; }

        public string Xml { get; set; }
    }  

    public class WsFederationMessageTestSet
    {
        public WsFederationMessage WsFederationMessage { get; set; }

        public string Xml { get; set; }
    }
}