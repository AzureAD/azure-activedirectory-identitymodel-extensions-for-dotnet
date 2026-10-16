// Copyright (c) Microsoft Corporation. All rights reserved.
// Licensed under the MIT License.

namespace Microsoft.IdentityModel.Protocols.OpenIdConnect
{
    /// <summary>
    /// Defines client assertion types for token requests. See: <see href="https://datatracker.ietf.org/doc/html/rfc7523"/>.
    /// </summary>
    public static class OpenIdConnectClientAssertionTypes
    {
        /// <summary>
        /// Indicates the 'jwt-bearer' client assertion type. See: <see href="https://datatracker.ietf.org/doc/html/rfc7523#section-2.2"/>.
        /// </summary>
        public const string JwtBearer = "urn:ietf:params:oauth:client-assertion-type:jwt-bearer";
    }
}