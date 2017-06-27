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
using static Microsoft.IdentityModel.Logging.LogHelper;

namespace Microsoft.IdentityModel.Tokens.Saml
{
    /// <summary>
    /// Represents the Attribute element.
    /// </summary>
    public class SamlAttribute
    {
        private string _name;
        private string _nameSpace;
        private string _originalIssuer;
        private string _attributeValueXsiType = ClaimValueTypes.String;
        private List<Claim> _claims;
        private string _claimType;

        // TODO remove this internal
        /// <summary>
        /// Initializes a new instance of <see cref="SamlAttribute"/>.
        /// </summary>
        internal SamlAttribute()
        {
            Values = new Collection<string>();
        }

        /// <summary>
        /// Initializes a new instance of <see cref="SamlAttribute"/>s.
        /// </summary>
        /// <param name="ns">The namespace of the attribute.</param>
        /// <param name="name">The name of the attribute.</param>
        /// <param name="value">The value of the attribute.</param>
        public SamlAttribute(string ns, string name, string value)
            : this(ns, name, new string[] { value })
        {
        }

        /// <summary>
        /// Initializes a new instance of <see cref="SamlAttribute"/>.
        /// </summary>
        /// <param name="ns">The namespace of the attribute.</param>
        /// <param name="name">The name of the attribute.</param>
        /// <param name="values"><see cref="IEnumerable{String}"/>.</param>
        public SamlAttribute(string ns, string name, IEnumerable<string> values)
        {
            Values = (values == null) ? throw LogArgumentNullException(LogMessages.IDX11504) : new List<string>(values);

            Name = name;
            Namespace = ns;
            _claimType = string.IsNullOrEmpty(_nameSpace) ? _name : _nameSpace + "/" + _name;
        }

        /// <summary>
        /// Gets a collection of <see cref="ICollection{String}"/> representing attributes.
        /// </summary>
        public ICollection<string> Values { get; }

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
                    throw LogArgumentNullException(nameof(value));

                int indexOfHash = value.IndexOf('#');
                if (indexOfHash == -1)
                    throw LogExceptionMessage(new SecurityTokenInvalidAudienceException("value, SR.GetString(SR.ID4254)")); ;

                string prefix = value.Substring(0, indexOfHash);
                if (prefix.Length == 0)
                    throw LogExceptionMessage(new ArgumentException("value SR.GetString(SR.ID4254)"));

                string suffix = value.Substring(indexOfHash + 1);
                if (suffix.Length == 0)
                {
                    throw LogExceptionMessage(new ArgumentException("value, SR.GetString(SR.ID4254)"));
                }

                _attributeValueXsiType = value;
            }
        }

        /// <summary>
        /// Gets or sets the name of the attribute.
        /// </summary>
        public string Name
        {
            get { return _name; }
            set
            {
                if (string.IsNullOrEmpty(value))
                    throw LogArgumentNullException(nameof(value));

                _name = value;
            }
        }

        /// <summary>
        /// Gets or sets the namespace of the attribute.
        /// </summary>
        public string Namespace
        {
            get { return _nameSpace; }
            set
            {
                if (string.IsNullOrEmpty(value))
                    throw LogArgumentNullException(nameof(value));

                _nameSpace = value;
            }
        }

        /// <summary>
        /// Gets or sets the string that represents the OriginalIssuer of the SAML Attribute.
        /// </summary>
        public string OriginalIssuer
        {
            get { return _originalIssuer; }
            set
            {
                if (string.IsNullOrEmpty(value))
                    throw LogArgumentNullException(nameof(value));

                _originalIssuer = value;
            }
        }

        // TODO - hide this behind SamlToken.Claims OR SamlAssertion.Claims.
        internal virtual ReadOnlyCollection<Claim> ExtractClaims()
        {
            if (_claims == null)
            {
                List<Claim> tempClaims = new List<Claim>(Values.Count);
                foreach (var value in Values)
                {
                    if (value == null)
                        throw LogExceptionMessage(new SamlSecurityTokenException(LogMessages.IDX11504));

                    tempClaims.Add(new Claim(_claimType, value));
                }

                _claims = tempClaims;
            }

            return _claims.AsReadOnly();
        }
    }
}
