// Copyright (c) Microsoft Corporation. All rights reserved.
// Licensed under the MIT License.

using System.Text;

namespace Microsoft.IdentityModel.Protocols.OpenIdConnect
{
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
        public const string Sid = "sid";
        public const string State = "state";
        public const string TargetLinkUri = "target_link_uri";
        public const string TokenType = "token_type";
        public const string UiLocales = "ui_locales";
        public const string UserId = "user_id";
        public const string Username = "username";
        public const string VersionTelemetry = "x-client-ver";
    }

    /// <summary>
    /// Parameter names for OpenIdConnect UTF8 bytes.
    /// </summary>
    public static class OpenIdConnectParameterUtf8Bytes
    {
        public static readonly byte[] AccessToken = Encoding.UTF8.GetBytes("access_token");
        public static readonly byte[] AcrValues = Encoding.UTF8.GetBytes("acr_values");
        public static readonly byte[] ClaimsLocales = Encoding.UTF8.GetBytes("claims_locales");
        public static readonly byte[] ClientAssertion = Encoding.UTF8.GetBytes("client_assertion");
        public static readonly byte[] ClientAssertionType = Encoding.UTF8.GetBytes("client_assertion_type");
        public static readonly byte[] ClientId = Encoding.UTF8.GetBytes("client_id");
        public static readonly byte[] ClientSecret = Encoding.UTF8.GetBytes("client_secret");
        public static readonly byte[] Code = Encoding.UTF8.GetBytes("code");
        public static readonly byte[] Display = Encoding.UTF8.GetBytes("display");
        public static readonly byte[] DomainHint = Encoding.UTF8.GetBytes("domain_hint");
        public static readonly byte[] Error = Encoding.UTF8.GetBytes("error");
        public static readonly byte[] ErrorDescription = Encoding.UTF8.GetBytes("error_description");
        public static readonly byte[] ErrorUri = Encoding.UTF8.GetBytes("error_uri");
        public static readonly byte[] ExpiresIn = Encoding.UTF8.GetBytes("expires_in");
        public static readonly byte[] GrantType = Encoding.UTF8.GetBytes("grant_type");
        public static readonly byte[] Iss = Encoding.UTF8.GetBytes("iss");
        public static readonly byte[] IdToken = Encoding.UTF8.GetBytes("id_token");
        public static readonly byte[] IdTokenHint = Encoding.UTF8.GetBytes("id_token_hint");
        public static readonly byte[] IdentityProvider = Encoding.UTF8.GetBytes("identity_provider");
        public static readonly byte[] LoginHint = Encoding.UTF8.GetBytes("login_hint");
        public static readonly byte[] MaxAge = Encoding.UTF8.GetBytes("max_age");
        public static readonly byte[] Nonce = Encoding.UTF8.GetBytes("nonce");
        public static readonly byte[] Password = Encoding.UTF8.GetBytes("password");
        public static readonly byte[] PostLogoutRedirectUri = Encoding.UTF8.GetBytes("post_logout_redirect_uri");
        public static readonly byte[] Prompt = Encoding.UTF8.GetBytes("prompt");
        public static readonly byte[] RedirectUri = Encoding.UTF8.GetBytes("redirect_uri");
        public static readonly byte[] RefreshToken = Encoding.UTF8.GetBytes("refresh_token");
        public static readonly byte[] RequestUri = Encoding.UTF8.GetBytes("request_uri");
        public static readonly byte[] Resource = Encoding.UTF8.GetBytes("resource");
        public static readonly byte[] ResponseMode = Encoding.UTF8.GetBytes("response_mode");
        public static readonly byte[] ResponseType = Encoding.UTF8.GetBytes("response_type");
        public static readonly byte[] Scope = Encoding.UTF8.GetBytes("scope");
        public static readonly byte[] SkuTelemetry = Encoding.UTF8.GetBytes("x-client-SKU");
        public static readonly byte[] SessionState = Encoding.UTF8.GetBytes("session_state");
        public static readonly byte[] Sid = Encoding.UTF8.GetBytes("sid");
        public static readonly byte[] State = Encoding.UTF8.GetBytes("state");
        public static readonly byte[] TargetLinkUri = Encoding.UTF8.GetBytes("target_link_uri");
        public static readonly byte[] TokenType = Encoding.UTF8.GetBytes("token_type");
        public static readonly byte[] UiLocales = Encoding.UTF8.GetBytes("ui_locales");
        public static readonly byte[] UserId = Encoding.UTF8.GetBytes("user_id");
        public static readonly byte[] Username = Encoding.UTF8.GetBytes("username");
        public static readonly byte[] VersionTelemetry = Encoding.UTF8.GetBytes("x-client-ver");
    }
#pragma warning restore 1591

}
