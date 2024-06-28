// Copyright (c) Microsoft Corporation. All rights reserved.
// Licensed under the MIT License.

namespace Microsoft.IdentityModel.Protocols.OpenIdConnect
{
    /// <summary>
    /// Defines grant types for token requests. See <see href="https://datatracker.ietf.org/doc/html/rfc6749"/>.
    /// </summary>
    public static class OpenIdConnectGrantTypes
    {
        /// <summary>
        /// Indicates the 'authorization_code' grant type. See <see href="https://datatracker.ietf.org/doc/html/rfc6749#section-4.1"/>.
        /// </summary>
        public const string AuthorizationCode = "authorization_code";

        /// <summary>
        /// Indicates the 'refresh_token' grant type. See <see href="https://datatracker.ietf.org/doc/html/rfc6749#section-6"/>.
        /// </summary>
        public const string RefreshToken = "refresh_token";

        /// <summary>
        /// Indicates the 'password' grant type. See <see href="https://datatracker.ietf.org/doc/html/rfc6749#section-4.3"/>.
        /// </summary>
        public const string Password = "password";

        /// <summary>
        /// Indicates the 'client_credentials' grant type. See <see href="https://datatracker.ietf.org/doc/html/rfc6749#section-4.4"/>.
        /// </summary>
        public const string ClientCredentials = "client_credentials";
    }
}
