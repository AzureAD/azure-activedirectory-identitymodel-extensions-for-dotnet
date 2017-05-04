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
using System;
using Microsoft.IdentityModel.Logging;

namespace Microsoft.IdentityModel.Tokens.Saml2
{
    /// <summary>
    /// Comparison class supporting multi-part keys for a dicitionary
    /// </summary>
    internal class Saml2AttributeKeyComparer : IEqualityComparer<Saml2AttributeKeyComparer.AttributeKey>
    {
        public class AttributeKey
        {
            string _friendlyName;
            int _hashCode;
            string _name;
            string _nameFormat;
            string _valueType;
            string _originalIssuer;

            internal string FriendlyName { get { return _friendlyName; } }
            internal string Name { get { return _name; } }
            internal string NameFormat { get { return _nameFormat; } }
            internal string ValueType { get { return _valueType; } }
            internal string OriginalIssuer { get { return _originalIssuer; } }

            public AttributeKey(Saml2Attribute attribute)
            {
                if (attribute == null)
                    throw LogHelper.LogArgumentNullException(nameof(attribute));

                _friendlyName = String.Empty;
                _name = attribute.Name;
                _nameFormat = String.Empty;
                _valueType = attribute.AttributeValueXsiType ?? String.Empty;
                _originalIssuer = attribute.OriginalIssuer ?? String.Empty;

                ComputeHashCode();
            }

            // TODO - see if needed for SAML2
            //public AttributeKey( Saml2Attribute attribute )
            //{
            //    if ( attribute == null )
            //    {
            //        throw LogHelper.ExceptionUtility.ThrowHelperArgumentNull( "attribute" );
            //    }

            //    _friendlyName = attribute.FriendlyName ?? String.Empty;
            //    _name = attribute.Name;
            //    _nameFormat = attribute.NameFormat == null ? String.Empty : attribute.NameFormat.OriginalString;
            //    _namespace = String.Empty;
            //    _valueType = attribute.AttributeValueXsiType ?? String.Empty;
            //    _originalIssuer = attribute.OriginalIssuer ?? String.Empty;

            //    ComputeHashCode();
            //}

            public override int GetHashCode()
            {
                return _hashCode;
            }

            void ComputeHashCode()
            {
                _hashCode = _name.GetHashCode();
                _hashCode ^= _friendlyName.GetHashCode();
                _hashCode ^= _nameFormat.GetHashCode();
                _hashCode ^= _valueType.GetHashCode();
                _hashCode ^= _originalIssuer.GetHashCode();
            }
        }

        #region IEqualityComparer<AttributeKey> Members

        public bool Equals(AttributeKey x, AttributeKey y)
        {
            return x.Name.Equals(y.Name, StringComparison.Ordinal)
                && x.FriendlyName.Equals(y.FriendlyName, StringComparison.Ordinal)
                && x.ValueType.Equals(y.ValueType, StringComparison.Ordinal)
                && x.OriginalIssuer.Equals(y.OriginalIssuer, StringComparison.Ordinal)
                && x.NameFormat.Equals(y.NameFormat, StringComparison.Ordinal);
        }

        public int GetHashCode(AttributeKey obj)
        {
            return obj.GetHashCode();
        }

        #endregion
    };
}
