using System;
using System.Collections.Generic;
using System.Linq;
using System.Threading.Tasks;

namespace Microsoft.IdentityModel.Protocols.OpenIdConnect
{
    /// <summary>
    /// OpenIdProviderConfiguration Names
    /// http://openid.net/specs/openid-connect-discovery-1_0.html#ProviderMetadata 
    /// </summary>
    public static class OpenIdProviderMetadataNames
    {
#pragma warning disable 1591
        public const string AuthorizationEndpoint = "authorization_endpoint";
        public const string CheckSessionIframe = "check_session_iframe";
        public const string Discovery = ".well-known/openid-configuration";
        public const string EndSessionEndpoint = "end_session_endpoint";
        public const string IdTokenSigningAlgValuesSupported = "id_token_signing_alg_values_supported";
        public const string JwksUri = "jwks_uri";
        public const string Issuer = "issuer";
        public const string MicrosoftMultiRefreshToken = "microsoft_multi_refresh_token";
        public const string ResponseModesSupported = "response_modes_supported";
        public const string ResponseTypesSupported = "response_types_supported";
        public const string SubjectTypesSupported = "subject_types_supported";
        public const string TokenEndpoint = "token_endpoint";
        public const string TokenEndpointAuthMethodsSupported = "token_endpoint_auth_methods_supported";
        public const string UserInfoEndpoint = "userinfo_endpoint";
#pragma warning restore 1591
    }
}
