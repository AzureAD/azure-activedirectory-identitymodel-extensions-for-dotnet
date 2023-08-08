// Copyright (c) Microsoft Corporation. All rights reserved.
// Licensed under the MIT License.

using System.Text;

namespace Microsoft.IdentityModel.Protocols.OpenIdConnect
{
    /// <summary>
    /// OpenIdProviderConfiguration MetadataName
    /// http://openid.net/specs/openid-connect-discovery-1_0.html#ProviderMetadata 
    /// </summary>
    public static class OpenIdProviderMetadataNames
    {
#pragma warning disable 1591
        public const string AcrValuesSupported = "acr_values_supported";
        public const string AuthorizationEndpoint = "authorization_endpoint";
        public const string CheckSessionIframe = "check_session_iframe";
        public const string ClaimsLocalesSupported = "claims_locales_supported";
        public const string ClaimsParameterSupported = "claims_parameter_supported";
        public const string ClaimsSupported = "claims_supported";
        public const string ClaimTypesSupported = "claim_types_supported";
        public const string Discovery = ".well-known/openid-configuration";
        public const string DisplayValuesSupported = "display_values_supported";
        public const string EndSessionEndpoint = "end_session_endpoint";
        public const string FrontchannelLogoutSessionSupported = "frontchannel_logout_session_supported";
        public const string FrontchannelLogoutSupported = "frontchannel_logout_supported";
        public const string HttpLogoutSupported = "http_logout_supported";
        public const string GrantTypesSupported = "grant_types_supported";
        public const string IdTokenEncryptionAlgValuesSupported = "id_token_encryption_alg_values_supported";
        public const string IdTokenEncryptionEncValuesSupported = "id_token_encryption_enc_values_supported";
        public const string IdTokenSigningAlgValuesSupported = "id_token_signing_alg_values_supported";
        public const string IntrospectionEndpoint = "introspection_endpoint";
        public const string IntrospectionEndpointAuthMethodsSupported = "introspection_endpoint_auth_methods_supported";
        public const string IntrospectionEndpointAuthSigningAlgValuesSupported = "introspection_endpoint_auth_signing_alg_values_supported";
        public const string JwksUri = "jwks_uri";
        public const string Issuer = "issuer";
        public const string LogoutSessionSupported = "logout_session_supported";
        public const string MicrosoftMultiRefreshToken = "microsoft_multi_refresh_token";
        public const string OpPolicyUri = "op_policy_uri";
        public const string OpTosUri = "op_tos_uri";
        public const string RegistrationEndpoint = "registration_endpoint";
        public const string RequestObjectEncryptionAlgValuesSupported = "request_object_encryption_alg_values_supported";
        public const string RequestObjectEncryptionEncValuesSupported = "request_object_encryption_enc_values_supported";
        public const string RequestObjectSigningAlgValuesSupported = "request_object_signing_alg_values_supported";
        public const string RequestParameterSupported = "request_parameter_supported";
        public const string RequestUriParameterSupported = "request_uri_parameter_supported";
        public const string RequireRequestUriRegistration = "require_request_uri_registration";
        public const string ResponseModesSupported = "response_modes_supported";
        public const string ResponseTypesSupported = "response_types_supported";
        public const string ServiceDocumentation = "service_documentation";
        public const string ScopesSupported = "scopes_supported";
        public const string SubjectTypesSupported = "subject_types_supported";
        public const string TokenEndpoint = "token_endpoint";
        public const string TokenEndpointAuthMethodsSupported = "token_endpoint_auth_methods_supported";
        public const string TokenEndpointAuthSigningAlgValuesSupported = "token_endpoint_auth_signing_alg_values_supported";
        public const string UILocalesSupported = "ui_locales_supported";
        public const string UserInfoEndpoint = "userinfo_endpoint";
        public const string UserInfoEncryptionAlgValuesSupported = "userinfo_encryption_alg_values_supported";
        public const string UserInfoEncryptionEncValuesSupported = "userinfo_encryption_enc_values_supported";
        public const string UserInfoSigningAlgValuesSupported = "userinfo_signing_alg_values_supported";
    }
#pragma warning restore 1591

    /// <summary>
    /// OpenIdProviderConfiguration MetadataName - UTF8Bytes
    /// http://openid.net/specs/openid-connect-discovery-1_0.html#ProviderMetadata
    /// </summary>
    internal static class OpenIdProviderMetadataUtf8Bytes
    {
        public static readonly byte[] AcrValuesSupported = Encoding.UTF8.GetBytes("acr_values_supported");
        public static readonly byte[] AuthorizationEndpoint = Encoding.UTF8.GetBytes("authorization_endpoint");
        public static readonly byte[] CheckSessionIframe = Encoding.UTF8.GetBytes("check_session_iframe");
        public static readonly byte[] ClaimsLocalesSupported = Encoding.UTF8.GetBytes("claims_locales_supported");
        public static readonly byte[] ClaimsParameterSupported = Encoding.UTF8.GetBytes("claims_parameter_supported");
        public static readonly byte[] ClaimsSupported = Encoding.UTF8.GetBytes("claims_supported");
        public static readonly byte[] ClaimTypesSupported = Encoding.UTF8.GetBytes("claim_types_supported");
        public static readonly byte[] Discovery = Encoding.UTF8.GetBytes(".well-known/openid-configuration");
        public static readonly byte[] DisplayValuesSupported = Encoding.UTF8.GetBytes("display_values_supported");
        public static readonly byte[] EndSessionEndpoint = Encoding.UTF8.GetBytes("end_session_endpoint");
        public static readonly byte[] FrontchannelLogoutSessionSupported = Encoding.UTF8.GetBytes("frontchannel_logout_session_supported");
        public static readonly byte[] FrontchannelLogoutSupported = Encoding.UTF8.GetBytes("frontchannel_logout_supported");
        public static readonly byte[] HttpLogoutSupported = Encoding.UTF8.GetBytes("http_logout_supported");
        public static readonly byte[] GrantTypesSupported = Encoding.UTF8.GetBytes("grant_types_supported");
        public static readonly byte[] IdTokenEncryptionAlgValuesSupported = Encoding.UTF8.GetBytes("id_token_encryption_alg_values_supported");
        public static readonly byte[] IdTokenEncryptionEncValuesSupported = Encoding.UTF8.GetBytes("id_token_encryption_enc_values_supported");
        public static readonly byte[] IdTokenSigningAlgValuesSupported = Encoding.UTF8.GetBytes("id_token_signing_alg_values_supported");
        public static readonly byte[] IntrospectionEndpoint = Encoding.UTF8.GetBytes("introspection_endpoint");
        public static readonly byte[] IntrospectionEndpointAuthMethodsSupported = Encoding.UTF8.GetBytes("introspection_endpoint_auth_methods_supported");
        public static readonly byte[] IntrospectionEndpointAuthSigningAlgValuesSupported = Encoding.UTF8.GetBytes("introspection_endpoint_auth_signing_alg_values_supported");
        public static readonly byte[] JwksUri = Encoding.UTF8.GetBytes("jwks_uri");
        public static readonly byte[] Issuer = Encoding.UTF8.GetBytes("issuer");
        public static readonly byte[] LogoutSessionSupported = Encoding.UTF8.GetBytes("logout_session_supported");
        public static readonly byte[] MicrosoftMultiRefreshToken = Encoding.UTF8.GetBytes("microsoft_multi_refresh_token");
        public static readonly byte[] OpPolicyUri = Encoding.UTF8.GetBytes("op_policy_uri");
        public static readonly byte[] OpTosUri = Encoding.UTF8.GetBytes("op_tos_uri");
        public static readonly byte[] RegistrationEndpoint = Encoding.UTF8.GetBytes("registration_endpoint");
        public static readonly byte[] RequestObjectEncryptionAlgValuesSupported = Encoding.UTF8.GetBytes("request_object_encryption_alg_values_supported");
        public static readonly byte[] RequestObjectEncryptionEncValuesSupported = Encoding.UTF8.GetBytes("request_object_encryption_enc_values_supported");
        public static readonly byte[] RequestObjectSigningAlgValuesSupported = Encoding.UTF8.GetBytes("request_object_signing_alg_values_supported");
        public static readonly byte[] RequestParameterSupported = Encoding.UTF8.GetBytes("request_parameter_supported");
        public static readonly byte[] RequestUriParameterSupported = Encoding.UTF8.GetBytes("request_uri_parameter_supported");
        public static readonly byte[] RequireRequestUriRegistration = Encoding.UTF8.GetBytes("require_request_uri_registration");
        public static readonly byte[] ResponseModesSupported = Encoding.UTF8.GetBytes("response_modes_supported");
        public static readonly byte[] ResponseTypesSupported = Encoding.UTF8.GetBytes("response_types_supported");
        public static readonly byte[] ServiceDocumentation = Encoding.UTF8.GetBytes("service_documentation");
        public static readonly byte[] ScopesSupported = Encoding.UTF8.GetBytes("scopes_supported");
        public static readonly byte[] SubjectTypesSupported = Encoding.UTF8.GetBytes("subject_types_supported");
        public static readonly byte[] TokenEndpoint = Encoding.UTF8.GetBytes("token_endpoint");
        public static readonly byte[] TokenEndpointAuthMethodsSupported = Encoding.UTF8.GetBytes("token_endpoint_auth_methods_supported");
        public static readonly byte[] TokenEndpointAuthSigningAlgValuesSupported = Encoding.UTF8.GetBytes("token_endpoint_auth_signing_alg_values_supported");
        public static readonly byte[] UILocalesSupported = Encoding.UTF8.GetBytes("ui_locales_supported");
        public static readonly byte[] UserInfoEndpoint = Encoding.UTF8.GetBytes("userinfo_endpoint");
        public static readonly byte[] UserInfoEncryptionAlgValuesSupported = Encoding.UTF8.GetBytes("userinfo_encryption_alg_values_supported");
        public static readonly byte[] UserInfoEncryptionEncValuesSupported = Encoding.UTF8.GetBytes("userinfo_encryption_enc_values_supported");
        public static readonly byte[] UserInfoSigningAlgValuesSupported = Encoding.UTF8.GetBytes("userinfo_signing_alg_values_supported");
    }
}
