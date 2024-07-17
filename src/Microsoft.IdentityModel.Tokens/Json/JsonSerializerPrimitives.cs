// Licensed to the .NET Foundation under one or more agreements.
// The .NET Foundation licenses this file to you under the MIT license.
// See the LICENSE file in the project root for more information.

using System;
using System.Collections.Generic;

namespace Microsoft.IdentityModel.Tokens.Json
{
    internal static class JsonSerializerPrimitives
    {
#if !NET45
        public static bool TryAllStringClaimsAsDateTime()
        {
            return AppContextSwitches.TryAllStringClaimsAsDateTime;
        }
#endif

        /// <summary>
        /// This is a non-exhaustive list of claim types that are not expected to be DateTime values
        /// sourced from expected Entra V1 and V2 claims, OpenID Connect claims, and a selection of
        /// restricted claim names.
        /// </summary>
        private static readonly HashSet<string> s_knownNonDateTimeClaimTypes = new(StringComparer.Ordinal)
        {
            // Header Values.
            "alg",
            "cty",
            "crit",
            "enc",
            "jku",
            "jwk",
            "kid",
            "typ",
            "x5c",
            "x5t",
            "x5t#S256",
            "x5u",
            "zip",
            // JWT claims.
            "acr",
            "acrs",
            "access_token",
            "account_type",
            "acct",
            "actor",
            "actort",
            "actortoken",
            "aio",
            "altsecid",
            "amr",
            "app_displayname",
            "appid",
            "appidacr",
            "at_hash",
            "aud",
            "authorization_code",
            "azp",
            "azpacr",
            "c_hash",
            "cnf",
            "capolids",
            "ctry",
            "email",
            "family_name",
            "fwd",
            "gender",
            "given_name",
            "groups",
            "hasgroups",
            "idp",
            "idtyp",
            "in_corp",
            "ipaddr",
            "iss",
            "jti",
            "login_hint",
            "name",
            "nameid",
            "nickname",
            "nonce",
            "oid",
            "onprem_sid",
            "phone_number",
            "phone_number_verified",
            "pop_jwk",
            "preferred_username",
            "prn",
            "puid",
            "pwd_url",
            "rh",
            "role",
            "roles",
            "secaud",
            "sid",
            "sub",
            "tenant_ctry",
            "tenant_region_scope",
            "tid",
            "unique_name",
            "upn",
            "uti",
            "ver",
            "verified_primary_email",
            "verified_secondary_email",
            "vnet",
            "website",
            "wids",
            "xms_cc",
            "xms_edov",
            "xms_pdl",
            "xms_pl",
            "xms_tpl",
            "ztdid"
        };

        internal static bool IsKnownToNotBeDateTime(string claimType)
        {
            if (string.IsNullOrEmpty(claimType))
                return true;

            if (s_knownNonDateTimeClaimTypes.Contains(claimType))
                return true;

            return false;
        }
    }
}
