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
using System.Collections.ObjectModel;
using System.Security.Claims;
using Microsoft.IdentityModel.Tokens.Saml;

namespace Microsoft.IdentityModel.Tests
{
    public class ReferenceSaml
    {
        public static SamlAssertion SamlAssertion
        {
            get
            {
                return new SamlAssertion(Default.SamlAssertionID, Default.Issuer, DateTime.Parse(Default.IssueInstant), SamlConditions, null, new Collection<SamlStatement> { SamlAttributeStatement })
                {
                    Signature = Default.Signature
                };
            }
        }

        public static SamlConditions SamlConditions
        {
            get
            {
                var audiences = new Collection<string> { Default.Audience };
                var conditions = new Collection<SamlCondition> { new SamlAudienceRestrictionCondition(audiences) };
                return new SamlConditions(Default.NotBefore, Default.NotOnOrAfter, conditions);
            }
        }

        public static SamlSubject SamlSubject
        {
            get { return new SamlSubject(string.Empty, string.Empty,string.Empty, new string[] { Default.SamlConfirmationMethod }, string.Empty); }
        }

        public static SamlAttributeStatement SamlAttributeStatement
        {
            get { return GetAttributeStatement(SamlSubject, ClaimSets.DefaultClaims); }
        }

        public static SamlAttributeStatement GetAttributeStatement(SamlSubject subject, IEnumerable<Claim> claims)
        {
            string defaultNamespace = "http://schemas.xmlsoap.org/ws/2005/05/identity/claims";
            Collection<SamlAttribute> attributes = new Collection<SamlAttribute>();
            foreach (var claim in claims)
            {
                string type = claim.Type;
                string name = type;
                if (type.Contains("/"))
                {
                    int lastSlashIndex = type.LastIndexOf('/');
                    name = type.Substring(lastSlashIndex + 1);
                }

                type = defaultNamespace;

                string value = claim.Value;
                SamlAttribute attribute = new SamlAttribute(type, name, claim.Value);
                attributes.Add(attribute);
            }

            return new SamlAttributeStatement(subject, attributes);
        }
    }
}
