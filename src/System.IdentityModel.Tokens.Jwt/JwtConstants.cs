//-----------------------------------------------------------------------
// Copyright (c) Microsoft Open Technologies, Inc.
// All Rights Reserved
// Apache License 2.0
//
// Licensed under the Apache License, Version 2.0 (the "License");
// you may not use this file except in compliance with the License.
// You may obtain a copy of the License at
// 
// http://www.apache.org/licenses/LICENSE-2.0
// 
// Unless required by applicable law or agreed to in writing, software
// distributed under the License is distributed on an "AS IS" BASIS,
// WITHOUT WARRANTIES OR CONDITIONS OF ANY KIND, either express or implied.
// See the License for the specific language governing permissions and
// limitations under the License.
//-----------------------------------------------------------------------

namespace System.IdentityModel.Tokens.Jwt
{
    /// <summary>
    /// Constants for Json Web tokens.
    /// </summary>
    public static class JwtConstants
    {
        /// <summary>
        /// Short header type.
        /// </summary>
        public const string HeaderType = "JWT";

        /// <summary>
        /// Long header type.
        /// </summary>
        public const string HeaderTypeAlt = "http://openid.net/specs/jwt/1.0";

        /// <summary>
        /// Short token type.
        /// </summary>
        public const string TokenType = "JWT";

        /// <summary>
        /// Long token type.
        /// </summary>
        public const string TokenTypeAlt = "urn:ietf:params:oauth:token-type:jwt";

        /// <summary>
        /// Token format: 'header.payload.signature'. Signature is optional, but '.' is required.
        /// </summary>
        public const string JsonCompactSerializationRegex = @"^[A-Za-z0-9-_]+\.[A-Za-z0-9-_]+\.[A-Za-z0-9-_]*$";

        /// <summary>
        /// When mapping json to .Net Claim(s), if the value was not a string (or an enumeration of strings), the ClaimValue will serialized using the current JSON serializer, a property will be added with the .Net type and the ClaimTypeValue will be set to 'JsonClaimValueType'.
        /// </summary>
        public const string JsonClaimValueType = "JSON";
    }

    /// <summary>
    /// List of algorithms see: http://tools.ietf.org/html/draft-ietf-jose-json-web-algorithms-26#section-3
    /// </summary>
    public struct JwtAlgorithms
    {
        /// <summary>
        /// see: http://tools.ietf.org/html/draft-ietf-jose-json-web-algorithms-26#section-3
        /// </summary>
        public const string ECDSA_SHA256    = "ES256";

        /// <summary>
        /// see: http://tools.ietf.org/html/draft-ietf-jose-json-web-algorithms-26#section-3
        /// </summary>
        public const string ECDSA_SHA384    = "ES384";

        /// <summary>
        /// see: http://tools.ietf.org/html/draft-ietf-jose-json-web-algorithms-26#section-3
        /// </summary>
        public const string ECDSA_SHA512    = "ES512";

        /// <summary>
        /// see: http://tools.ietf.org/html/draft-ietf-jose-json-web-algorithms-26#section-3
        /// </summary>
        public const string HMAC_SHA256     = "HS256";

        /// <summary>
        /// see: http://tools.ietf.org/html/draft-ietf-jose-json-web-algorithms-26#section-3
        /// </summary>
        public const string HMAC_SHA384     = "HS384";

        /// <summary>
        /// see: http://tools.ietf.org/html/draft-ietf-jose-json-web-algorithms-26#section-3
        /// </summary>
        public const string HMAC_SHA512     = "HS512";

        /// <summary>
        /// see: http://tools.ietf.org/html/draft-ietf-jose-json-web-algorithms-26#section-3
        /// </summary>
        public const string NONE            = "none";

        /// <summary>
        /// see: http://tools.ietf.org/html/draft-ietf-jose-json-web-algorithms-26#section-3
        /// </summary>
        public const string RSA_SHA256      = "RS256";

        /// <summary>
        /// see: http://tools.ietf.org/html/draft-ietf-jose-json-web-algorithms-26#section-3
        /// </summary>
        public const string RSA_SHA384      = "RS384";

        /// <summary>
        /// see: http://tools.ietf.org/html/draft-ietf-jose-json-web-algorithms-26#section-3
        /// </summary>
        public const string RSA_SHA512      = "RS512";
    }

    /// <summary>
    /// List of header parameter names see: http://tools.ietf.org/html/draft-ietf-oauth-json-web-token-20#section-5.
    /// </summary>
    public struct JwtHeaderParameterNames
    {
        /// <summary>
        /// see: http://tools.ietf.org/html/draft-ietf-oauth-json-web-token-20#section-5
        /// </summary>
        public const string Alg = "alg";

        /// <summary>
        /// see: http://tools.ietf.org/html/draft-ietf-oauth-json-web-token-20#section-5
        /// </summary>
        public const string Cty = "cty";

        /// <summary>
        /// see: http://tools.ietf.org/html/draft-ietf-oauth-json-web-token-20#section-5
        /// </summary>
        public const string Kid = "kid";

        /// <summary>
        /// see: http://tools.ietf.org/html/draft-ietf-oauth-json-web-token-20#section-5
        /// </summary>
        public const string Jku = "jku";

        /// <summary>
        /// see: http://tools.ietf.org/html/draft-ietf-oauth-json-web-token-20#section-5
        /// </summary>
        public const string Jwk = "jwk";

        /// <summary>
        /// see: http://tools.ietf.org/html/draft-ietf-oauth-json-web-token-20#section-5
        /// </summary>
        public const string Typ = "typ";

        /// <summary>
        /// see: http://tools.ietf.org/html/draft-ietf-oauth-json-web-token-20#section-5
        /// </summary>
        public const string X5c = "x5c";

        /// <summary>
        /// see: http://tools.ietf.org/html/draft-ietf-oauth-json-web-token-20#section-5
        /// </summary>
        public const string X5t = "x5t";

        /// <summary>
        /// see: http://tools.ietf.org/html/draft-ietf-oauth-json-web-token-20#section-5
        /// </summary>
        public const string X5u = "x5u";
    }
    
    /// <summary>
    /// List of registered claims from different sources
    /// http://tools.ietf.org/html/draft-ietf-oauth-json-web-token-20#section-4
    /// http://openid.net/specs/openid-connect-core-1_0.html#IDToken
    /// </summary>
    public struct JwtRegisteredClaimNames
    {
        /// <summary>
        /// http://tools.ietf.org/html/draft-ietf-oauth-json-web-token-20#section-4
        /// </summary>
        public const string Actort = "actort";

        /// <summary>
        /// http://openid.net/specs/openid-connect-core-1_0.html#IDToken
        /// </summary>
        public const string Acr = "acr";

        /// <summary>
        /// http://openid.net/specs/openid-connect-core-1_0.html#IDToken
        /// </summary>
        public const string Amr = "amr";

        /// <summary>
        /// http://tools.ietf.org/html/draft-ietf-oauth-json-web-token-20#section-4
        /// </summary>
        public const string Aud = "aud";

        /// <summary>
        /// http://openid.net/specs/openid-connect-core-1_0.html#IDToken
        /// </summary>
        public const string AuthTime = "auth_time";

        /// <summary>
        /// http://openid.net/specs/openid-connect-core-1_0.html#IDToken
        /// </summary>
        public const string Azp = "azp";

        /// <summary>
        /// http://tools.ietf.org/html/draft-ietf-oauth-json-web-token-20#section-4
        /// </summary>
        public const string Birthdate = "birthdate";

        /// <summary>
        /// http://tools.ietf.org/html/draft-ietf-oauth-json-web-token-20#section-4
        /// </summary>
        public const string CHash = "c_hash";

        /// <summary>
        /// http://openid.net/specs/openid-connect-core-1_0.html#CodeIDToken
        /// </summary>
        public const string AtHash = "at_hash";

        /// <summary>
        /// http://tools.ietf.org/html/draft-ietf-oauth-json-web-token-20#section-4
        /// </summary>
        public const string Email = "email";

        /// <summary>
        /// http://tools.ietf.org/html/draft-ietf-oauth-json-web-token-20#section-4
        /// </summary>
        public const string Exp = "exp";

        /// <summary>
        /// http://tools.ietf.org/html/draft-ietf-oauth-json-web-token-20#section-4
        /// </summary>
        public const string Gender = "gender";

        /// <summary>
        /// http://tools.ietf.org/html/draft-ietf-oauth-json-web-token-20#section-4
        /// </summary>
        public const string FamilyName = "family_name";

        /// <summary>
        /// http://tools.ietf.org/html/draft-ietf-oauth-json-web-token-20#section-4
        /// </summary>
        public const string GivenName = "given_name";

        /// <summary>
        /// http://tools.ietf.org/html/draft-ietf-oauth-json-web-token-20#section-4
        /// </summary>
        public const string Iat = "iat";

        /// <summary>
        /// http://tools.ietf.org/html/draft-ietf-oauth-json-web-token-20#section-4
        /// </summary>
        public const string Iss = "iss";

        /// <summary>
        /// http://tools.ietf.org/html/draft-ietf-oauth-json-web-token-20#section-4
        /// </summary>
        public const string Jti = "jti";

        /// <summary>
        /// http://tools.ietf.org/html/draft-ietf-oauth-json-web-token-20#section-4
        /// </summary>
        public const string NameId = "nameid";

        /// <summary>
        /// http://tools.ietf.org/html/draft-ietf-oauth-json-web-token-20#section-4
        /// </summary>
        public const string Nonce = "nonce";

        /// <summary>
        /// http://tools.ietf.org/html/draft-ietf-oauth-json-web-token-20#section-4
        /// </summary>
        public const string Nbf = "nbf";

        /// <summary>
        /// http://tools.ietf.org/html/draft-ietf-oauth-json-web-token-20#section-4
        /// </summary>
        public const string Prn = "prn";

        /// <summary>
        /// http://tools.ietf.org/html/draft-ietf-oauth-json-web-token-20#section-4
        /// </summary>
        public const string Sub = "sub";

        /// <summary>
        /// http://tools.ietf.org/html/draft-ietf-oauth-json-web-token-20#section-4
        /// </summary>
        public const string Typ = "typ";

        /// <summary>
        /// http://tools.ietf.org/html/draft-ietf-oauth-json-web-token-20#section-4
        /// </summary>
        public const string UniqueName = "unique_name";

        /// <summary>
        /// http://tools.ietf.org/html/draft-ietf-oauth-json-web-token-20#section-4
        /// </summary>
        public const string Website = "website";
    }
}
