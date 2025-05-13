// Copyright (c) Microsoft Corporation. All rights reserved.
// Licensed under the MIT License.

using System;
using System.Security.Claims;

namespace Microsoft.IdentityModel.Tokens.Saml2
{
#pragma warning disable RS0016 // Add public types and members to the declared API
    /// <summary>
    /// Defines a ClaimsIdentity that knows how to fish claims out of Saml2Token
    /// </summary>
    public class Saml2ClaimsIdentity : ClaimsIdentity
    {
        private Saml2SecurityToken _saml2SecurityToken;
        private Saml2AttributeStatement _saml2AttributeStatement;
        /// <summary>
        /// Creates a new instance of <see cref="Saml2ClaimsIdentity"/>.
        /// </summary>
        public Saml2ClaimsIdentity(Saml2SecurityToken saml2SecurityToken)
        {
            _saml2SecurityToken = saml2SecurityToken;
            foreach (var statement in _saml2SecurityToken.Assertion.Statements)
            {
                if (statement is Saml2AttributeStatement attributeStatement)
                {
                    _saml2AttributeStatement = attributeStatement;
                    break;
                }
            }
        }

        /// <summary>
        /// Returns a value that indicates whether the <see cref="ClaimsIdentity"/> contains a claim of the specified type and value.
        /// </summary>
        /// <param name="type">the claim name.</param>
        /// <param name="value">the claims value.</param>
        /// <returns></returns>
        public override bool HasClaim(string type, string value)
        {
            if (_saml2AttributeStatement == null)
                return false;

            if (string.IsNullOrEmpty(type) || string.IsNullOrEmpty(value))
                return false;

            foreach (var attribute in _saml2AttributeStatement.Attributes)
            {
                if (StringComparer.Ordinal.Equals(attribute.Name, type))
                {
                    foreach (string str in attribute.Values)
                    {
                        if (StringComparer.Ordinal.Equals(str, value))
                            return true;
                    }
                }
            }

            return false;
        }
    }
#pragma warning restore RS0016 // Add public types and members to the declared API}
}
