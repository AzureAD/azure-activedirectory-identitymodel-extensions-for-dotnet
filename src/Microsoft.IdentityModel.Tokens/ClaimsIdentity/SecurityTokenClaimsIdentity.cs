// Copyright (c) Microsoft Corporation. All rights reserved.
// Licensed under the MIT License.

using System;
using System.Collections.Generic;
using System.Security.Claims;

namespace Microsoft.IdentityModel.Tokens
{
    /// <summary>
    /// An implementation of <see cref="ClaimsIdentity"/> that uses a backing SecurityToken to retrieve claims in a performant manner.
    /// </summary>
    [Serializable]
    public class SecurityTokenClaimsIdentity : CaseSensitiveClaimsIdentity
    {
        // Claims that are "removed" from the SecurityToken
        [NonSerialized]
        private readonly HashSet<string> _removedClaims = [];

        /// <summary>
        /// Initializes an instance of <see cref="SecurityTokenClaimsIdentity"/>.
        /// </summary>
        public SecurityTokenClaimsIdentity() : base()
        {
        }

        /// <summary>
        /// Initializes an instance of <see cref="SecurityTokenClaimsIdentity"/>.
        /// </summary>
        /// <param name="authenticationType">The authentication method used to establish this identity.</param>
        /// <param name="nameType">The <see cref="Claim.Type"/> used when obtaining the value of <see cref="ClaimsIdentity.Name"/>.</param>
        /// <param name="roleType">The <see cref="Claim.Type"/> used when performing logic for <see cref="ClaimsPrincipal.IsInRole"/>.</param>
        public SecurityTokenClaimsIdentity(string authenticationType, string nameType, string roleType) :
            base(authenticationType, nameType, roleType)
        {
        }

        /// <summary>
        /// Checks JsonWebToken for the claim first,
        /// if not found, checks base claims collection.
        /// </summary>
        /// <param name="type"></param>
        /// <returns></returns>
        public override Claim FindFirst(string type)
        {
            if (SecurityToken is ClaimsProvider claimsProvider)
            {
                Claim claim = claimsProvider.GetClaim(type);
                if (claim is not null && !_removedClaims.Contains(type))
                    return claim;
            }

            return base.FindFirst(type);
        }


        /// <inheritdoc/>
        public override Claim FindFirst(Predicate<Claim> match)
        {
            return base.FindFirst(match);
        }

        /// <inheritdoc/>
        public override IEnumerable<Claim> FindAll(string type)
        {
            List<Claim> claims = new List<Claim>();

            return claims;
        }
        /// <inheritdoc/>
        public override IEnumerable<Claim> FindAll(Predicate<Claim> match)
        {
            return base.FindAll(match);
        }

        /// <inheritdoc/>
        public override bool HasClaim(string type, string value)
        {
            if (SecurityToken is ClaimsProvider claimsProvider)
            {
                if (claimsProvider.HasClaim(type, value) && !_removedClaims.Contains(type))
                    return true;
            }

            return base.HasClaim(type, value);
        }

        /// <inheritdoc/>
        public override bool HasClaim(Predicate<Claim> match)
        {
            return base.HasClaim(match);
        }

        // Add claims to base collection since claims cannot be added to SecurityToken
        /// <inheritdoc/>
        public override void AddClaim(Claim claim)
        {
            _ = claim ?? throw new ArgumentNullException(nameof(claim));

            base.AddClaim(claim);

            _removedClaims.Remove(claim.Type);
        }

        // Add claims to base collection since claims cannot be added to SecurityToken
        /// <inheritdoc/>
        public override void AddClaims(IEnumerable<Claim> claims)
        {
            _ = claims ?? throw new ArgumentNullException(nameof(claims));

            foreach (Claim claim in claims)
            {
                if (claim == null)
                {
                    continue;
                }

                base.AddClaim(claim);

                _removedClaims.Remove(claim.Type);
            }
        }

        /// <inheritdoc/>
        public override void RemoveClaim(Claim claim)
        {
            if (!TryRemoveClaim(claim))
            {
                throw new InvalidOperationException("Claim cannot be removed.");
            }
        }

        /// <summary>
        /// Tries to remove  a claim from the base collection by reference.
        /// Since a claim cannot be removed from the SecurityToken,
        /// adds the claim name to the removed collection in this class, if it exists in SecurityToken.
        /// </summary>
        /// <param name="claim">Claim to remove.</param>
        /// <returns>True, if claim existed in and was removed from either base claims collection or SecurityToken; false, otherwise.</returns>
        public override bool TryRemoveClaim(Claim claim)
        {
            _ = claim ?? throw new ArgumentNullException(nameof(claim));

            bool removedFromJwt = false;
            if (SecurityToken is ClaimsProvider claimsProvider)
            {
                if (claim == null || _removedClaims.Contains(claim.Type))
                    return false;

                removedFromJwt = claimsProvider.HasClaim(claim.Type);
                if (removedFromJwt)
                    _removedClaims.Add(claim.Type);
            }

            return base.TryRemoveClaim(claim) | removedFromJwt;
        }

        //protected override Claim CreateClaim(BinaryReader reader) => base.CreateClaim(reader);

        //public override void WriteTo(BinaryWriter writer) => base.WriteTo(writer);

        //protected override void WriteTo(BinaryWriter writer, byte[] userData) => base.WriteTo(writer, userData);

        //protected override void GetObjectData(SerializationInfo info, StreamingContext context) => base.GetObjectData(info, context);

        //public override IEnumerable<Claim> Claims => base.Claims;
    }
}
