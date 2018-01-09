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
using static Microsoft.IdentityModel.Logging.LogHelper;

namespace Microsoft.IdentityModel.Tokens.Saml
{
    /// <summary>
    /// Comparison class supporting multi-part keys for a dicitionary
    /// </summary>
    public class SamlAttributeKeyComparer : IEqualityComparer<SamlAttributeKeyComparer.AttributeKey>
    {
        /// <summary>
        /// A class contains Saml attribute key.
        /// </summary>
        public class AttributeKey
        {
            int _hashCode;

            /// <summary>
            /// Represents the Saml Attribute Key.
            /// </summary>
            /// <param name="attribute"></param>
            public AttributeKey(SamlAttribute attribute)
            {
                if (attribute == null)
                {
                    throw LogArgumentNullException(nameof(attribute));
                }

                FriendlyName = String.Empty;
                Name = attribute.Name;
                NameFormat = String.Empty;
                Namespace = attribute.Namespace ?? String.Empty;
                ValueType = attribute.AttributeValueXsiType ?? String.Empty;
                OriginalIssuer = attribute.OriginalIssuer ?? String.Empty;

                ComputeHashCode();
            }

            internal string FriendlyName { get; }
            internal string Name { get; }
            internal string NameFormat { get; }
            internal string Namespace { get; }
            internal string OriginalIssuer { get; }
            internal string ValueType { get; }
            

            void ComputeHashCode()
            {
                _hashCode = Name.GetHashCode();
                _hashCode ^= FriendlyName.GetHashCode();
                _hashCode ^= NameFormat.GetHashCode();
                _hashCode ^= Namespace.GetHashCode();
                _hashCode ^= ValueType.GetHashCode();
                _hashCode ^= OriginalIssuer.GetHashCode();
            }

            /// <summary>
            /// Override GetHashCode function.
            /// </summary>
            /// <returns></returns>
            public override int GetHashCode()
            {
                return _hashCode;
            }
        }

        #region IEqualityComparer<AttributeKey> Members

        /// <summary>
        /// Compare AttributeKeys.
        /// </summary>
        /// <param name="x"></param>
        /// <param name="y"></param>
        /// <returns></returns>
        public bool Equals(AttributeKey x, AttributeKey y)
        {
            return x.Name.Equals(y.Name, StringComparison.Ordinal)
                && x.FriendlyName.Equals(y.FriendlyName, StringComparison.Ordinal)
                && x.ValueType.Equals(y.ValueType, StringComparison.Ordinal)
                && x.OriginalIssuer.Equals(y.OriginalIssuer, StringComparison.Ordinal)
                && x.NameFormat.Equals(y.NameFormat, StringComparison.Ordinal)
                && x.Namespace.Equals(y.Namespace, StringComparison.Ordinal);
        }

        /// <summary>
        /// Get the AttributeKey's hash code.
        /// </summary>
        /// <param name="obj"></param>
        /// <returns></returns>
        public int GetHashCode(AttributeKey obj)
        {
            return obj.GetHashCode();
        }

        #endregion
    };
}
