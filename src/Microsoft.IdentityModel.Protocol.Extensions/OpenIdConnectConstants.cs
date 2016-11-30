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

namespace Microsoft.IdentityModel.Protocols
{
    /// <summary>
    /// Well known endpoints for AzureActiveDirectory
    /// </summary>
    public static class ActiveDirectoryOpenIdConnectEndpoints
    {
        #pragma warning disable 1591
        public const string Authorize = "oauth2/authorize";
        public const string Logout = "oauth2/logout";
        public const string Token = "oauth2/token";
        #pragma warning restore 1591
    }

    /// <summary>
    /// Names for Json Web Key Values
    /// </summary>
    public static class JsonWebKeyParameterNames
    {
        #pragma warning disable 1591
        public const string Alg = "alg";
        public const string E = "e";
        public const string KeyOps = "key_ops";
        public const string Keys = "keys";
        public const string Kid = "kid";
        public const string Kty = "kty";
        public const string N = "n";
        public const string Use = "use";
        public const string X5c = "x5c";
        public const string X5t = "x5t";
        public const string X5u = "x5u";
        #pragma warning restore 1591
    }

    /// <summary>
    /// Constants for JsonWebKeyUse (sec 4.2)
    /// http://tools.ietf.org/html/draft-ietf-jose-json-web-key-27#section-4
    /// </summary>
    public static class JsonWebKeyUseNames
    {
        #pragma warning disable 1591
        public const string Sig = "sig";
        public const string Enc = "enc";
        #pragma warning restore 1591
    }

    /// <summary>
    /// Constants for JsonWebAlgorithms  "kty" Key Type (sec 6.1)
    /// http://tools.ietf.org/html/draft-ietf-jose-json-web-algorithms-27#section-6.1
    /// </summary>
    public static class JsonWebAlgorithmsKeyTypes
    {
        #pragma warning disable 1591
        public const string EllipticCurve = "EC";
        public const string RSA = "RSA";
        public const string Octet = "oct";
        #pragma warning restore 1591
    }

    /// <summary>
    /// Parameter names for OpenIdConnect.
    /// </summary>
    public static class OpenIdConnectParameterNames
    {
        #pragma warning disable 1591
        public const string AccessToken = "access_token";
        public const string AcrValues = "acr_values";
        public const string ClaimsLocales = "claims_locales";
        public const string ClientAssertion = "client_assertion";
        public const string ClientAssertionType = "client_assertion_type";
        public const string ClientId = "client_id";
        public const string ClientSecret = "client_secret";
        public const string Code = "code";
        public const string Display = "display";
        public const string DomainHint = "domain_hint";
        public const string Error = "error";
        public const string ErrorDescription = "error_description";
        public const string ErrorUri = "error_uri";
        public const string ExpiresIn = "expires_in";
        public const string GrantType = "grant_type";
        public const string Iss = "iss";
        public const string IdToken = "id_token";
        public const string IdTokenHint = "id_token_hint";
        public const string IdentityProvider = "identity_provider";
        public const string LoginHint = "login_hint";
        public const string MaxAge = "max_age";
        public const string Nonce = "nonce";
        public const string Password = "password";
        public const string PostLogoutRedirectUri = "post_logout_redirect_uri";
        public const string Prompt = "prompt";
        public const string RedirectUri = "redirect_uri";
        public const string RefreshToken = "refresh_token";
        public const string RequestUri = "request_uri";
        public const string Resource = "resource";
        public const string ResponseMode = "response_mode";
        public const string ResponseType = "response_type";
        public const string Scope = "scope";
        public const string SkuTelemetry = "x-client-SKU";
        public const string SessionState = "session_state";
        public const string State = "state";
        public const string TargetLinkUri = "target_link_uri";
        public const string Token = "token";
        public const string TokenType = "token_type";
        public const string UiLocales = "ui_locales";
        public const string UserId = "user_id";
        public const string Username = "username";
        public const string VersionTelemetry = "x-client-ver";
        #pragma warning restore 1591
    }

    /// <summary>
    /// RequestTypes for OpenIdConnect.
    /// </summary>
    /// <remarks>Can be used to determine the message type.</remarks>
    public enum OpenIdConnectRequestType
    {
        #pragma warning disable 1591
        AuthenticationRequest,
        LogoutRequest,
        TokenRequest,
        #pragma warning restore 1591
    }

    /// <summary>
    /// Response modes for OpenIdConnect.
    /// </summary>
    public static class OpenIdConnectResponseModes
    {
        #pragma warning disable 1591
        public const string Query = "query";
        public const string FormPost = "form_post";
        public const string Fragment = "fragment";
        #pragma warning restore 1591
    }

    /// <summary>
    /// Response types for OpenIdConnect.
    /// </summary>
    public static class OpenIdConnectResponseTypes
    {
        #pragma warning disable 1591
        public const string CodeIdToken = "code id_token";
        public const string IdToken = "id_token";
        #pragma warning restore 1591
    }

    /// <summary>
    /// Specific scope values that are interesting to OpenID Connect.  See http://openid.net/specs/openid-connect-messages-1_0.html#scopes
    /// </summary>
    public static class OpenIdConnectScopes
    {
        #pragma warning disable 1591
        public const string OpenId = "openid";
        public const string OpenIdProfile = "openid profile";
        public const string UserImpersonation = "user_impersonation";
        #pragma warning restore 1591
    }

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