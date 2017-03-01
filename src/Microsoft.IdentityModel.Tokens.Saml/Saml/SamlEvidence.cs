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
using System.Collections.ObjectModel;
using Microsoft.IdentityModel.Logging;

namespace Microsoft.IdentityModel.Tokens.Saml
{
    public class SamlEvidence
    {
        Collection<string> _assertionIdReferences = new Collection<string>();
        Collection<SamlAssertion> _assertions = new Collection<SamlAssertion>();

        // TODO - remove this internal
        internal SamlEvidence()
        {
        }

        public SamlEvidence(IEnumerable<string> assertionIdReferences)
            : this(assertionIdReferences, null)
        {
        }

        public SamlEvidence(IEnumerable<SamlAssertion> assertions)
            : this(null, assertions)
        {
        }

        public SamlEvidence(IEnumerable<string> assertionIdReferences, IEnumerable<SamlAssertion> assertions)
        {
            if (assertionIdReferences == null && assertions == null)
                throw LogHelper.LogExceptionMessage(new SamlSecurityTokenException("SAMLEvidenceShouldHaveOneAssertion"));

            if (assertionIdReferences != null)
            {
                foreach (string idReference in assertionIdReferences)
                {
                    if (string.IsNullOrEmpty(idReference))
                        throw LogHelper.LogExceptionMessage(new SamlSecurityTokenException("SAMLEntityCannotBeNullOrEmpty"));

                    _assertionIdReferences.Add(idReference);
                }
            }

            if (assertions != null)
            {
                foreach (SamlAssertion assertion in assertions)
                {
                    if (assertion == null)
                        throw LogHelper.LogExceptionMessage(new SamlSecurityTokenException("SAMLEntityCannotBeNullOrEmpty"));

                    _assertions.Add(assertion);
                }
            }
        }

        public ICollection<string> AssertionIdReferences
        {
            get { return _assertionIdReferences; }
        }

        public ICollection<SamlAssertion> Assertions
        {
            get { return _assertions; }
        }

        // TODO - validate when writing
        //void CheckObjectValidity()
        //{
        //    if ((_assertions.Count == 0) && (_assertionIdReferences.Count == 0))
        //        throw LogHelper.LogExceptionMessage(new SamlSecurityTokenException("SAMLEvidenceShouldHaveOneAssertion"));
        //}
    }
}
