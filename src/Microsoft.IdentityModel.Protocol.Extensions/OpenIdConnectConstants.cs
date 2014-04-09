// Copyright (c) Microsoft Open Technologies, Inc. All rights reserved. See License.txt in the project root for license information.

namespace Microsoft.IdentityModel.Protocols
{

    /// <summary>
    /// Constant names for Json Web Key Values
    /// </summary>
    public static class JsonWebKeysValueNames
    {
        #pragma warning disable 1591
        public static readonly string Keys = "keys";
        public static readonly string Kty = "kty";
        public static readonly string Use = "use";
        public static readonly string Kid = "Kid";
        public static readonly string X5t = "x5t";
        public static readonly string X5c = "x5c";
        public static readonly string E   = "e";
        public static readonly string N   = "n";
        #pragma warning restore 1591
    }

    /// <summary>
    /// Specific scope values that are interesting to OpenID Connect.  See http://openid.net/specs/openid-connect-messages-1_0.html#scopes
    /// </summary>
    public static class OpenIdConnectScopes
    {
        #pragma warning disable 1591
        public static readonly string OpenId = "openid";
        public static readonly string OpenId_Profile = "openid profile";
        public static readonly string User_Impersonation = "user_impersonation";
        #pragma warning restore 1591
    }

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
    /// 
    /// </summary>
    public static class OpenIdConnectMetadataNames
    {
        #pragma warning disable 1591
        public const string Authorization_Endpoint = "authorization_endpoint";
        public const string Check_Session_Iframe = "check_session_iframe";
        public const string End_Session_Endpoint = "end_session_endpoint";
        public const string Id_Token_Signing_Alg_Balues_Supported = "id_token_signing_alg_values_supported";
        public const string Jwks_Uri = "jwks_uri";
        public const string Issuer = "issuer";
        public const string Microsoft_Multi_Refresh_Token = "microsoft_multi_refresh_token";
        public const string Response_Modes_Supported = "response_modes_supported";
        public const string Response_Types_Supported = "response_types_supported";
        public const string Subject_Types_Supported = "subject_types_supported";
        public const string Token_Endpoint = "token_endpoint";
        public const string Token_Endpoint_Auth_Methods_Supported = "token_endpoint";
        #pragma warning restore 1591
    }

    /// <summary>
    /// Parameter names for OpenIdConnect.
    /// </summary>
    public static class OpenIdConnectParameterNames
    {
        #pragma warning disable 1591
        public const string Access_Token = "access_token"; 
        public const string Acr_Values = "acr_values";
        public const string Claims_Locales = "claims_locales";
        public const string Client_Assertion = "client_assertion";
        public const string Client_Assertion_Type = "client_assertion_type";
        public const string Client_Id = "client_id";
        public const string Client_Secret = "client_secret";
        public const string Code = "code";
        public const string Display = "display";
        public const string Domain_Hint = "domain_hint";
        public const string Error = "error";
        public const string Error_Description = "error_description";
        public const string Error_Uri = "error_uri";
        public const string Expires_In = "expires_in";
        public const string Grant_Type = "grant_type";
        public const string Iss = "iss";
        public const string Id_Token = "id_token";
        public const string Id_Token_Hint = "id_token_hint";
        public const string Identity_Provider = "identity_provider";
        public const string Login_Hint = "login_hint";
        public const string Max_Age = "max_age";
        public const string Nonce = "nonce";
        public const string Password = "password";
        public const string Post_Logout_Redirect_Uri = "post_logout_redirect_uri";
        public const string Prompt = "prompt";
        public const string Redirect_Uri = "redirect_uri";
        public const string Request_Uri = "request_uri";
        public const string Resource = "resource";        
        public const string Response_Mode = "response_mode";        
        public const string Response_Type = "response_type";       
        public const string Scope = "scope";
        public const string Session_State = "session_state";
        public const string State = "state";
        public const string Target_Link_Uri = "target_link_uri";
        public const string Token = "token";
        public const string Token_Type = "token_type";
        public const string Ui_Locales = "ui_locales";
        public const string User_Id = "user_id";
        public const string Username = "username";
        #pragma warning restore 1591
    }

    /// <summary>
    /// Response types for OpenIdConnect.
    /// </summary>
    public static class OpenIdConnectResponseTypes
    {
        #pragma warning disable 1591
        public const string Code_Id_Token = "code id_token";
        public const string Id_Token = "id_token";
        #pragma warning restore 1591
    }


    /// <summary>
    /// Response types for OpenIdConnect.
    /// </summary>
    public static class OpenIdConnectResponseModes
    {
#pragma warning disable 1591
        public const string Query = "query";
        public const string FormPost = "form_post";
        public const string Fragment = "fragment";
#pragma warning restore 1591
    }

}