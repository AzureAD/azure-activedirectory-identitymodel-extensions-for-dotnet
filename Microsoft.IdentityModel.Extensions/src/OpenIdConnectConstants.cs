// Copyright (c) Microsoft Open Technologies, Inc. All rights reserved. See License.txt in the project root for license information.

namespace Microsoft.IdentityModel.Protocols
{
    /// <summary>
    /// Specific scope values that are interesting to OpenID Connect.  See http://openid.net/specs/openid-connect-messages-1_0.html#scopes
    /// </summary>
    public static class OpenIdConnectScopes
    {
        #pragma warning disable 1591

        public static readonly string Openid = "openid";
        public static readonly string Openid_Profile = "openid profile";

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
        public const string Refresh_token = "refresh_token";
        public const string Request_Uri = "request_uri";
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
}