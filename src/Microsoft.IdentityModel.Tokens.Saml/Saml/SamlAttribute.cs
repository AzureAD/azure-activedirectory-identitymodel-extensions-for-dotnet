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
using Microsoft.IdentityModel.Logging;

namespace Microsoft.IdentityModel.Tokens.Saml
{
    public class SamlAttribute
    {
        private string _name;
        private string _nameSpace;
        private Collection<string> _attributeValues = new Collection<string>();
        private string _originalIssuer;
        private string _attributeValueXsiType = ClaimValueTypes.String;
        private List<Claim> _claims;
        private string _claimType;

        // TODO remove this internal
        internal SamlAttribute()
        {
        }

        public SamlAttribute(string ns, string name, IEnumerable<string> values)
        {
            if (string.IsNullOrEmpty(ns))
                throw LogHelper.LogArgumentNullException(nameof(ns));

            if (string.IsNullOrEmpty(name))
                throw LogHelper.LogArgumentNullException(nameof(name));

            if (values == null)
                throw LogHelper.LogArgumentNullException(nameof(values));

            _name = name;
            _nameSpace = ns;
            _claimType = string.IsNullOrEmpty(_nameSpace) ? _name : _nameSpace + "/" + _name;

            foreach (string value in values)
            {
                if (value == null)
                    throw LogHelper.LogArgumentNullException("SAMLAttributeValueCannotBeNull");

                _attributeValues.Add(value);
            }

            if (_attributeValues.Count == 0)
                throw LogHelper.LogArgumentNullException("SAMLAttributeShouldHaveOneValue");
        }

        public string Name
        {
            get { return _name; }
            set
            {
                if (string.IsNullOrEmpty(value))
                    throw LogHelper.LogArgumentNullException(nameof(value));

                _name = value;
            }
        }

        public string Namespace
        {
            get { return _nameSpace; }
            set
            {
                if (string.IsNullOrEmpty(value))
                    throw LogHelper.LogArgumentNullException(nameof(value));

                _nameSpace = value;
            }
        }

        public ICollection<string> AttributeValues
        {
            get { return _attributeValues; }
        }

        /// <summary>
        /// Gets or Sets the string that represents the OriginalIssuer of the SAML Attribute.
        /// </summary>
        public string OriginalIssuer
        {
            get { return _originalIssuer; }
            set
            {
                if (string.IsNullOrEmpty(value))
                    throw LogHelper.LogArgumentNullException(nameof(value));

                _originalIssuer = value;
            }
        }

        // TODO don't think this is still needed
        /// <summary>
        /// Gets or sets the xsi:type of the values contained in the SAML Attribute.
        /// </summary>
        public string AttributeValueXsiType
        {
            get { return _attributeValueXsiType; }
            set
            {
                if (string.IsNullOrEmpty(value))
                    throw LogHelper.LogArgumentNullException(nameof(value));

                int indexOfHash = value.IndexOf('#');
                if (indexOfHash == -1)
                {
                    throw LogHelper.LogExceptionMessage(new SecurityTokenInvalidAudienceException("value, SR.GetString(SR.ID4254)")); ;
                }

                string prefix = value.Substring(0, indexOfHash);
                if (prefix.Length == 0)
                {
                    throw LogHelper.LogExceptionMessage(new ArgumentException("value SR.GetString(SR.ID4254)"));
                }

                string suffix = value.Substring(indexOfHash + 1);
                if (suffix.Length == 0)
                {
                    throw LogHelper.LogExceptionMessage(new ArgumentException("value, SR.GetString(SR.ID4254)"));
                }

                _attributeValueXsiType = value;
            }
        }

        // TODO - hide this behind SamlToken.Claims OR SamlAssertion.Claims.
        internal virtual ReadOnlyCollection<Claim> ExtractClaims()
        {
            if (_claims == null)
            {
                List<Claim> tempClaims = new List<Claim>(_attributeValues.Count);

                for (int i = 0; i < _attributeValues.Count; i++)
                {
                    if (_attributeValues[i] == null)
                        throw LogHelper.LogExceptionMessage(new SamlSecurityTokenException("SAMLAttributeValueCannotBeNull"));

                    tempClaims.Add(new Claim(_claimType, _attributeValues[i]));
                }
                _claims = tempClaims;
            }

            return _claims.AsReadOnly();
        }
    }
}
