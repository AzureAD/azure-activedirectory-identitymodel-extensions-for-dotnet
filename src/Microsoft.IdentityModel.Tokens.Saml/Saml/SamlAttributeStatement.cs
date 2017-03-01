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
    public class SamlAttributeStatement : SamlSubjectStatement
    {
        private Collection<SamlAttribute> _attributes = new Collection<SamlAttribute>();

        internal SamlAttributeStatement()
        {
        }

        public SamlAttributeStatement(SamlSubject samlSubject, IEnumerable<SamlAttribute> attributes)
            : base(samlSubject)
        {
            if (attributes == null)
                throw LogHelper.LogArgumentNullException(nameof(attributes));

            foreach (SamlAttribute attribute in attributes)
            {
                if (attribute == null)
                    throw LogHelper.LogExceptionMessage(new SamlSecurityTokenException("SAMLEntityCannotBeNullOrEmpty"));

                _attributes.Add(attribute);
            }
        }

        public IList<SamlAttribute> Attributes
        {
            get { return _attributes; }
        }

        // TODO - how to extract claims
        // SamlSecurityTokenHandler?
        //protected override void AddClaimsToList(IList<Claim> claims)
        //{
        //    if (claims == null)
        //        throw LogHelper.LogArgumentNullException(nameof(claims");

        //    for (int i = 0; i < attributes.Count; i++)
        //    {
        //        if (attributes[i] != null)
        //        {
        //            ReadOnlyCollection<Claim> attributeClaims = attributes[i].ExtractClaims();
        //            if (attributeClaims != null)
        //            {
        //                for (int j = 0; j < attributeClaims.Count; ++j)
        //                    if (attributeClaims[j] != null)
        //                        claims.Add(attributeClaims[j]);
        //            }
        //        }
        //    }
        //}
    }
}
