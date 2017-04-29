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
using Microsoft.IdentityModel.Logging;
using Microsoft.IdentityModel.Xml;

namespace Microsoft.IdentityModel.Tokens.Saml2
{
    /// <summary>
    /// Represents the Attribute element specified in [Saml2Core, 2.7.3.1].
    /// </summary>
    public class Saml2Attribute
    {
        private string _attributeValueXsiType = System.Security.Claims.ClaimValueTypes.String;
        private string _friendlyName;
        private string _name;
        private Uri _nameFormat;
        private Collection<string> _values = new Collection<string>();

        /// <summary>
        /// Initializes a new instance of the Saml2Attribute class.
        /// </summary>
        /// <param name="name">The name of the attribute.</param>
        public Saml2Attribute(string name)
        {
            if (string.IsNullOrEmpty(name))
                throw LogHelper.LogArgumentNullException(nameof(name));

            _name = name;
        }

        /// <summary>
        /// Initializes a new instance of the Saml2Attribute class.
        /// </summary>
        /// <param name="name">The name of the attribute.</param>
        /// <param name="values">The collection of values that define the attribute.</param>
        public Saml2Attribute(string name, IEnumerable<string> values)
            : this(name)
        {
            if (values == null)
                throw LogHelper.LogArgumentNullException(nameof(values));

            foreach (string value in values)
                _values.Add(value);
        }

        /// <summary>
        /// Initializes a new instance of the Saml2Attribute class.
        /// </summary>
        /// <param name="name">The name of the attribute.</param>
        /// <param name="value">The value of the attribute.</param>
        public Saml2Attribute(string name, string value)
            : this(name, new string[] { value })
        { }

        /// <summary>
        /// Gets or sets a string that provides a more human-readable form of the attribute's 
        /// name. [Saml2Core, 2.7.3.1]
        /// </summary>
        public string FriendlyName
        {
            get { return _friendlyName; }
            set { _friendlyName = XmlUtil.NormalizeEmptyString(value); }
        }

        /// <summary>
        /// Gets or sets the name of the attribute. [Saml2Core, 2.7.3.1]
        /// </summary>
        public string Name
        {
            get { return _name; }
            set
            {
                if (string.IsNullOrEmpty(value))
                    throw LogHelper.LogExceptionMessage(new ArgumentNullException(nameof(value)));

                _name = value;
            }
        }

        /// <summary>
        /// Gets or sets a URI reference representing the classification of the attribute 
        /// name for the purposes of interpreting the name. [Saml2Core, 2.7.3.1]
        /// </summary>
        public Uri NameFormat
        {
            get { return _nameFormat; }
            set
            {
                if (null != value && !value.IsAbsoluteUri)
                    throw LogHelper.LogArgumentNullException("nameof(value), ID0013");

                _nameFormat = value;
            }
        }

        /// <summary>
        /// Gets or sets the string that represents the OriginalIssuer of the this SAML Attribute.
        /// </summary>
        public string OriginalIssuer { get; set; }

        /// <summary>
        /// Gets or sets the xsi:type of the values contained in the SAML Attribute.
        /// </summary>
        public string AttributeValueXsiType
        {
            get { return _attributeValueXsiType; }
            set
            {
                if (string.IsNullOrEmpty(value))
                    throw LogHelper.LogArgumentNullException("nameof(value), ID4254");

                int indexOfHash = value.IndexOf('#');
                if (indexOfHash == -1)
                    throw LogHelper.LogArgumentNullException("nameof(value), ID4254");

                string prefix = value.Substring(0, indexOfHash);
                if (prefix.Length == 0)
                    throw LogHelper.LogArgumentNullException("nameof(value), ID4254");

                string suffix = value.Substring(indexOfHash + 1);
                if (suffix.Length == 0)
                    throw LogHelper.LogArgumentNullException("nameof(value), ID4254");

                _attributeValueXsiType = value;
            }
        }

        /// <summary>
        /// Gets the values of the attribute.
        /// </summary>
        public Collection<string> Values
        {
            get { return _values; }
        }
    }
}
