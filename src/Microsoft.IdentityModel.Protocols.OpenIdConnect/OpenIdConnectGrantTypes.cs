// Copyright (c) Microsoft Corporation. All rights reserved.
// Licensed under the MIT License.

namespace Microsoft.IdentityModel.Protocols.OpenIdConnect
{
    /// <summary>
    /// Grant types for token requests. See https://datatracker.ietf.org/doc/html/rfc6749.
    /// </summary>
    public static class OpenIdConnectGrantTypes
    {
#pragma warning disable 1591
        public const string AuthorizationCode = "authorization_code";
        public const string RefreshToken = "refresh_token";
        public const string Password = "password";
        public const string ClientCredentials = "client_credentials";
        public const string Saml2Bearer = "urn:ietf:params:oauth:grant-type:saml2-bearer";
        public const string JwtBearer = "urn:ietf:params:oauth:grant-type:jwt-bearer";
        public const string DeviceCode = "urn:ietf:params:oauth:grant-type:device_code";
        public const string TokenExchange = "urn:ietf:params:oauth:grant-type:token-exchange";
        public const string Ciba = "urn:openid:params:grant-type:ciba";
#pragma warning restore 1591
    }
}
