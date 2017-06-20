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
using System.Xml;
using static Microsoft.IdentityModel.Logging.LogHelper;

namespace Microsoft.IdentityModel.Tokens.Saml2
{
    /// <summary>
    /// Represents the identifier used for SAML assertions.
    /// </summary>
    /// <details>
    /// This identifier should be unique per [Saml2Core, 1.3.4] 
    /// and must fit the NCName xml schema definition, which is to say that
    /// it must begin with a letter or underscore. 
    /// </details>
    public class Saml2Id
    {
        /// <summary>
        /// Creates a new ID value based on a GUID.
        /// </summary>
        public Saml2Id()
            : this(UniqueId.CreateRandomId())
        {
        }

        /// <summary>
        /// Creates a new ID whose value is the given string.
        /// </summary>
        /// <param name="value">The Saml2 Id.</param>
        /// <exception cref="ArgumentException">If the value is not a valid NCName.</exception>
        public Saml2Id(string value)
        {
            if (string.IsNullOrEmpty(value))
                throw LogArgumentNullException(nameof(value));

            try
            {
                Value = XmlConvert.VerifyNCName(value);
            }
            catch (XmlException ex)
            {
                throw LogExceptionMessage(new ArgumentException(FormatInvariant(LogMessages.IDX10515, value), ex));
            }
        }

        /// <summary>
        /// Gets the identifier string.
        /// </summary>
        public string Value
        {
            get;
        }

        /// <summary>
        /// Compares two <see cref="Saml2Id"/> for equality.
        /// </summary>
        /// <param name="obj">Object to campare to.</param>
        /// <returns>True if this equals object.  False otherwise.</returns>
        public override bool Equals(object obj)
        {
            if (Object.ReferenceEquals(this, obj))
            {
                return true;
            }

            Saml2Id other = obj as Saml2Id;
            return (null != other) && StringComparer.Ordinal.Equals(Value, other.Value);
        }

        /// <summary>
        /// Gets the hash code for the <see cref="Saml2Id"/> as an integer. 
        /// </summary>
        /// <returns>The hash code for this object.</returns>
        public override int GetHashCode()
        {
            return Value.GetHashCode();
        }

        /// <summary>
        /// Gets the <see cref="Saml2Id"/> in text format.
        /// </summary>
        /// <returns>The string representation of this object.</returns>
        public override string ToString()
        {
            return Value;
        }
    }
}
