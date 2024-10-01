// Copyright (c) Microsoft Corporation. All rights reserved.
// Licensed under the MIT License.

using System;
using System.Collections.Generic;
using System.IO;
using System.Runtime.Serialization;
using System.Security.Claims;
using Microsoft.IdentityModel.Tokens;

namespace Microsoft.IdentityModel.JsonWebTokens
{
    /// <summary>
    /// An implementation of <see cref="ClaimsIdentity"/> that uses a backing JsonWebToken to retrieve claims in a performant manner.
    /// </summary>
    internal class JsonWebTokenClaimsIdentity : CaseSensitiveClaimsIdentity
    {
        private readonly HashSet<Claim> _addedClaims = new HashSet<Claim>();
        private readonly HashSet<Claim> _removedClaims = new HashSet<Claim>();

        /// <summary>
        /// Initializes an instance of <see cref="JsonWebTokenClaimsIdentity"/>.
        /// </summary>
        public JsonWebTokenClaimsIdentity() : base()
        {
        }

        /// <summary>
        /// Initializes an instance of <see cref="JsonWebTokenClaimsIdentity"/>.
        /// </summary>
        /// <param name="authenticationType">The authentication method used to establish this identity.</param>
        /// <param name="nameType">The <see cref="Claim.Type"/> used when obtaining the value of <see cref="ClaimsIdentity.Name"/>.</param>
        /// <param name="roleType">The <see cref="Claim.Type"/> used when performing logic for <see cref="ClaimsPrincipal.IsInRole"/>.</param>
        public JsonWebTokenClaimsIdentity(string authenticationType, string nameType, string roleType) :
            base(authenticationType, nameType, roleType)
        {
        }

        public override Claim FindFirst(string type)
        {
            JsonWebToken jsonWebToken = (JsonWebToken)BootstrapContext;
            jsonWebToken.TryGetPayloadValue(type, out IList<string> value);

            return new Claim(type, value[0]);
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

        public override void AddClaim(Claim claim)
        {
            if (BootstrapContext is JsonWebToken jsonWebToken)
            {

            }
            else
            {
                base.AddClaim(claim);
            }
        }

        public override void AddClaims(IEnumerable<Claim> claims)
        {
            base.AddClaims(claims);
        }

        public override void RemoveClaim(Claim claim)
        {
            base.RemoveClaim(claim);
        }

        public override bool TryRemoveClaim(Claim claim)
        {
            return base.TryRemoveClaim(claim);
        }

        protected override Claim CreateClaim(BinaryReader reader) => base.CreateClaim(reader);

        public override void WriteTo(BinaryWriter writer) => base.WriteTo(writer);

        protected override void WriteTo(BinaryWriter writer, byte[] userData) => base.WriteTo(writer, userData);

        protected override void GetObjectData(SerializationInfo info, StreamingContext context) => base.GetObjectData(info, context);

        public override IEnumerable<Claim> Claims => base.Claims;
    }
}
