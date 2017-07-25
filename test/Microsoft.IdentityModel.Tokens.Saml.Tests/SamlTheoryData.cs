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

using System.Collections.Generic;
using Microsoft.IdentityModel.Tests;

namespace Microsoft.IdentityModel.Tokens.Saml.Tests
{
    public class SamlTheoryData : TheoryDataBase
    {
        public SamlActionTestSet ActionTestSet { get; set; }

        public string Actor { get; set; }

        public TokenValidationParameters ActorTokenValidationParameters { get; set; }

        public SamlAdviceTestSet AdviceTestSet { get; set; }

        public SamlAssertionTestSet AssertionTestSet { get; set; }

        public SamlAttributeTestSet AttributeTestSet { get; set; }

        public SamlAttributeStatementTestSet AttributeStatementTestSet { get; set; }

        public SamlAudienceRestrictionConditionTestSet AudienceRestrictionConditionTestSet { get; set; }

        public SamlAuthenticationStatementTestSet AuthenticationStatementTestSet { get; set; }

        public IEnumerable<string> Audiences { get; set; }

        public SamlAuthorizationDecisionStatementTestSet AuthorizationDecisionTestSet { get; set; }

        public bool CanRead { get; set; }

        public SamlTokenTestSet TokenClaimsIdentitiesTestSet { get; set; }

        public SamlConditionsTestSet ConditionsTestSet { get; set; }

        public SamlEvidenceTestSet EvidenceTestSet { get; set; }

        public SecurityTokenHandler Handler { get; set; }

        public string Issuer { get; set; }

        public SamlSerializer SamlSerializer { get; set; }

        public SamlSecurityTokenTestSet SamlSecurityTokenTestSet { get; set; }

        public SamlSubjectTestSet SubjectTestSet { get; set; }

        public SecurityTokenDescriptor TokenDescriptor { get; set; }

        public string Token { get; set; }

        public TokenValidationParameters ValidationParameters { get; set; }

        public override string ToString()
        {
            return $"{TestId}, {ExpectedException}";
        }
    }
}
