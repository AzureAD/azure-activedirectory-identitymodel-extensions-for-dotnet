// Copyright (c) Microsoft Corporation. All rights reserved.
// Licensed under the MIT License.

using System;
using System.Collections.Generic;
using System.IO;
using System.Runtime.Serialization;
using System.Security.Claims;

namespace Microsoft.IdentityModel.Tokens
{
    /// <summary>
    /// An implementation of <see cref="ClaimsIdentity"/> that uses a backing JsonWebToken to retrieve claims in a performant manner.
    /// </summary>
    internal class NewClaimsIdentity : CaseSensitiveClaimsIdentity
    {
        // Claims that are "removedFromJwt" from JsonWebToken
        private readonly HashSet<string> _removedClaims = [];

        /// <summary>
        /// Initializes an instance of <see cref="NewClaimsIdentity"/>.
        /// </summary>
        public NewClaimsIdentity() : base()
        {
        }

        /// <summary>
        /// Initializes an instance of <see cref="NewClaimsIdentity"/>.
        /// </summary>
        /// <param name="authenticationType">The authentication method used to establish this identity.</param>
        /// <param name="nameType">The <see cref="Claim.Type"/> used when obtaining the value of <see cref="ClaimsIdentity.Name"/>.</param>
        /// <param name="roleType">The <see cref="Claim.Type"/> used when performing logic for <see cref="ClaimsPrincipal.IsInRole"/>.</param>
        public NewClaimsIdentity(string authenticationType, string nameType, string roleType) :
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
            if (SecurityToken is JsonWebToken jsonWebToken)
            {
                jsonWebToken.TryGetPayloadValue(type, out IList<string> value);
            }

            return base.FindFirst(type);
        }

        public override Claim FindFirst(Predicate<Claim> match)
        {
            return base.FindFirst(match);
        }

        public override IEnumerable<Claim> FindAll(string type)
        {
            JsonWebToken jsonWebToken = (JsonWebToken)BootstrapContext;
            jsonWebToken.TryGetPayloadValue(type, out IList<object> value);

            return new Claim(type, value[0]);
        }
        public override IEnumerable<Claim> FindAll(Predicate<Claim> match)
        {
            return base.FindAll(match);
        }

        public override bool HasClaim(string type, string value)
        {
            if (BootstrapContext is JsonWebToken jsonWebToken)
            {
                if (jsonWebToken.TryGetPayloadValue(type, out IList<string> values))
                    return values.Contains(value);
            }
            else
            {
                return base.HasClaim(type, value);
            }

            return false;
        }

        public override bool HasClaim(Predicate<Claim> match)
        {
            return base.HasClaim(match);
        }

        // Add claims to base collection since claims cannot be added to JsonWebToken
        public override void AddClaim(Claim claim)
        {
            base.AddClaim(claim);

            _removedClaims.Remove(claim.Type);
        }

        // Add claims to base collection since claims cannot be added to JsonWebToken
        public override void AddClaims(IEnumerable<Claim> claims)
        {
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

        public override void RemoveClaim(Claim claim)
        {
            if (!TryRemoveClaim(claim))
            {
                throw new InvalidOperationException("Claim cannot be removed.");
            }
        }

        /// <summary>
        /// Tries to remove  a claim from the base collection by reference.
        /// Since a claim cannot be removedFromJwt from the JsonWebToken,
        /// adds the claim name to the removedFromJwt collection in this class, if it exists in JsonWebToken.
        /// </summary>
        /// <param name="claim">Claim to remove.</param>
        /// <returns>True, if claim existed in and was removedFromJwt from either base claims collection or JsonWebToken; false, otherwise.</returns>
        public override bool TryRemoveClaim(Claim claim)
        {
            bool removedFromJwt = false;
            if (SecurityToken is JsonWebToken jsonWebToken)
            {
                if (claim == null || _removedClaims.Contains(claim.Type))
                    return false;

                removedFromJwt = jsonWebToken.TryGetPayloadValue(claim.Type, out object _);
                if (removedFromJwt)
                    _removedClaims.Add(claim.Type);
            }

            return base.TryRemoveClaim(claim) | removedFromJwt;
        }

        protected override Claim CreateClaim(BinaryReader reader) => base.CreateClaim(reader);

        public override void WriteTo(BinaryWriter writer) => base.WriteTo(writer);

        protected override void WriteTo(BinaryWriter writer, byte[] userData) => base.WriteTo(writer, userData);

        protected override void GetObjectData(SerializationInfo info, StreamingContext context) => base.GetObjectData(info, context);

        public override IEnumerable<Claim> Claims => base.Claims;
    }
}
