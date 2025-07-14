// Copyright (c) Microsoft Corporation. All rights reserved.
// Licensed under the MIT License.

using System;
using System.Collections.Generic;
using System.Linq;
using System.Security.Claims;

namespace Microsoft.IdentityModel.Tokens
{
    /// <summary>
    /// Builder for creating <see cref="CaseSensitiveClaimsIdentity"/> instances using a fluent API.
    /// </summary>
    public class CaseSensitiveClaimsIdentityBuilder
    {
        private string _authenticationType;
        private string _nameType;
        private string _roleType;
        private List<Claim> _claims;
        private ClaimsIdentity _baseClaimsIdentity;
        private SecurityToken _securityToken;

        /// <summary>
        /// Initializes a new instance of the <see cref="CaseSensitiveClaimsIdentityBuilder"/> class.
        /// </summary>
        private CaseSensitiveClaimsIdentityBuilder()
        {
            _claims = new List<Claim>();
        }

        /// <summary>
        /// Creates a new instance of <see cref="CaseSensitiveClaimsIdentityBuilder"/>.
        /// </summary>
        /// <returns>A new builder instance.</returns>
        public static CaseSensitiveClaimsIdentityBuilder Create()
        {
            return new CaseSensitiveClaimsIdentityBuilder();
        }

        /// <summary>
        /// Sets the authentication type for the claims identity.
        /// </summary>
        /// <param name="authenticationType">The authentication type.</param>
        /// <returns>The builder instance for method chaining.</returns>
        /// <exception cref="ArgumentNullException">Thrown when <paramref name="authenticationType"/> is null.</exception>
        public CaseSensitiveClaimsIdentityBuilder WithAuthenticationType(string authenticationType)
        {
            if (authenticationType == null)
                throw new ArgumentNullException(nameof(authenticationType));

            _authenticationType = authenticationType;
            return this;
        }

        /// <summary>
        /// Sets the name claim type for the claims identity.
        /// </summary>
        /// <param name="nameType">The name claim type.</param>
        /// <returns>The builder instance for method chaining.</returns>
        /// <exception cref="ArgumentNullException">Thrown when <paramref name="nameType"/> is null.</exception>
        public CaseSensitiveClaimsIdentityBuilder WithNameType(string nameType)
        {
            if (nameType == null)
                throw new ArgumentNullException(nameof(nameType));

            _nameType = nameType;
            return this;
        }

        /// <summary>
        /// Sets the role claim type for the claims identity.
        /// </summary>
        /// <param name="roleType">The role claim type.</param>
        /// <returns>The builder instance for method chaining.</returns>
        /// <exception cref="ArgumentNullException">Thrown when <paramref name="roleType"/> is null.</exception>
        public CaseSensitiveClaimsIdentityBuilder WithRoleType(string roleType)
        {
            if (roleType == null)
                throw new ArgumentNullException(nameof(roleType));

            _roleType = roleType;
            return this;
        }

        /// <summary>
        /// Adds a claim to the claims identity.
        /// </summary>
        /// <param name="claim">The claim to add.</param>
        /// <returns>The builder instance for method chaining.</returns>
        /// <exception cref="ArgumentNullException">Thrown when <paramref name="claim"/> is null.</exception>
        public CaseSensitiveClaimsIdentityBuilder WithClaim(Claim claim)
        {
            if (claim == null)
                throw new ArgumentNullException(nameof(claim));

            _claims.Add(claim);
            return this;
        }

        /// <summary>
        /// Adds a claim to the claims identity.
        /// </summary>
        /// <param name="type">The claim type.</param>
        /// <param name="value">The claim value.</param>
        /// <returns>The builder instance for method chaining.</returns>
        /// <exception cref="ArgumentNullException">Thrown when <paramref name="type"/> or <paramref name="value"/> is null.</exception>
        public CaseSensitiveClaimsIdentityBuilder WithClaim(string type, string value)
        {
            if (type == null)
                throw new ArgumentNullException(nameof(type));
            if (value == null)
                throw new ArgumentNullException(nameof(value));

            _claims.Add(new Claim(type, value));
            return this;
        }

        /// <summary>
        /// Adds multiple claims to the claims identity.
        /// </summary>
        /// <param name="claims">The claims to add.</param>
        /// <returns>The builder instance for method chaining.</returns>
        /// <exception cref="ArgumentNullException">Thrown when <paramref name="claims"/> is null.</exception>
        public CaseSensitiveClaimsIdentityBuilder WithClaims(IEnumerable<Claim> claims)
        {
            if (claims == null)
                throw new ArgumentNullException(nameof(claims));

            // Filter out null claims
            var validClaims = claims.Where(c => c != null);
            _claims.AddRange(validClaims);
            return this;
        }

        /// <summary>
        /// Sets the base claims identity to copy from.
        /// </summary>
        /// <param name="claimsIdentity">The claims identity to copy from.</param>
        /// <returns>The builder instance for method chaining.</returns>
        /// <exception cref="ArgumentNullException">Thrown when <paramref name="claimsIdentity"/> is null.</exception>
        public CaseSensitiveClaimsIdentityBuilder FromClaimsIdentity(ClaimsIdentity claimsIdentity)
        {
            if (claimsIdentity == null)
                throw new ArgumentNullException(nameof(claimsIdentity));

            _baseClaimsIdentity = claimsIdentity;
            return this;
        }

        /// <summary>
        /// Sets the security token associated with the claims identity.
        /// </summary>
        /// <param name="securityToken">The security token.</param>
        /// <returns>The builder instance for method chaining.</returns>
        public CaseSensitiveClaimsIdentityBuilder WithSecurityToken(SecurityToken securityToken)
        {
            _securityToken = securityToken;
            return this;
        }

        /// <summary>
        /// Builds the <see cref="CaseSensitiveClaimsIdentity"/> instance using the configured properties.
        /// </summary>
        /// <returns>A new <see cref="CaseSensitiveClaimsIdentity"/> instance.</returns>
        public CaseSensitiveClaimsIdentity Build()
        {
            CaseSensitiveClaimsIdentity identity = SelectAndCreateIdentity();

            // Add any additional claims if we have them and used copy constructor
            if (_claims.Any() && _baseClaimsIdentity != null)
            {
                // Add additional claims to the identity created from base
                foreach (var claim in _claims)
                {
                    identity.AddClaim(claim);
                }
            }

            // Set the security token if provided
            if (_securityToken != null)
            {
                identity.SecurityToken = _securityToken;
            }

            return identity;
        }

        /// <summary>
        /// Selects the appropriate constructor and creates the identity based on configured properties.
        /// </summary>
        /// <returns>A new <see cref="CaseSensitiveClaimsIdentity"/> instance.</returns>
        private CaseSensitiveClaimsIdentity SelectAndCreateIdentity()
        {
            // 1. If base ClaimsIdentity is provided, use copy constructor
            if (_baseClaimsIdentity != null)
            {
                return new CaseSensitiveClaimsIdentity(_baseClaimsIdentity);
            }

            // 2. If claims + authentication type + name type + role type are provided, use full constructor
            if (_claims.Any() && !string.IsNullOrEmpty(_authenticationType) && 
                !string.IsNullOrEmpty(_nameType) && !string.IsNullOrEmpty(_roleType))
            {
                return new CaseSensitiveClaimsIdentity(_claims, _authenticationType, _nameType, _roleType);
            }

            // 3. If claims + authentication type are provided, use claims + auth constructor
            if (_claims.Any() && !string.IsNullOrEmpty(_authenticationType))
            {
                return new CaseSensitiveClaimsIdentity(_claims, _authenticationType);
            }

            // 4. If only claims are provided, use claims constructor
            if (_claims.Any())
            {
                return new CaseSensitiveClaimsIdentity(_claims);
            }

            // 5. If authentication type + name type + role type are provided, use types constructor
            if (!string.IsNullOrEmpty(_authenticationType) && 
                !string.IsNullOrEmpty(_nameType) && !string.IsNullOrEmpty(_roleType))
            {
                return new CaseSensitiveClaimsIdentity(_authenticationType, _nameType, _roleType);
            }

            // 6. If only authentication type is provided, use auth constructor
            if (!string.IsNullOrEmpty(_authenticationType))
            {
                return new CaseSensitiveClaimsIdentity(_authenticationType);
            }

            // 7. Otherwise, use default constructor
            return new CaseSensitiveClaimsIdentity();
        }
    }
}