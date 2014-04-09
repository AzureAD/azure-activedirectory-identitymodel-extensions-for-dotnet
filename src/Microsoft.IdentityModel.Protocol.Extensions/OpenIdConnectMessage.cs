// Copyright (c) Microsoft Open Technologies, Inc. All rights reserved. See License.txt in the project root for license information.

using System;
using System.Collections.Generic;
using System.Security.Cryptography.X509Certificates;

namespace Microsoft.IdentityModel.Protocols
{
    /// <summary>
    /// Provides access to common OpenIdConnect request parameters.
    /// </summary>
    public class OpenIdConnectMessage : AuthenticationProtocolMessage
    {
        /// <summary>
        /// Initializes a new instance of the <see cref="OpenIdConnectMessage"/> class.
        /// </summary>
        public OpenIdConnectMessage() : this(string.Empty) {}

        /// <summary>
        /// Initializes an instance of <see cref="AuthenticationProtocolMessage"/> class with a specific issuerAddress.
        /// </summary>
        public OpenIdConnectMessage(string issuerAddress) : base(issuerAddress) {}

        /// <summary>
        /// Initializes a new instance of the <see cref="OpenIdConnectMessage"/> class.
        /// </summary>
        /// <param name="openIdConnectMessage"> an <see cref="OpenIdConnectMessage"/> to copy.</param>        
        public OpenIdConnectMessage(OpenIdConnectMessage openIdConnectMessage)
        {
            if (openIdConnectMessage == null)
            {
                return;
            }

            foreach (KeyValuePair<string, string> keyValue in openIdConnectMessage.Parameters)
            {
                SetParameter(keyValue.Key, keyValue.Value);
            }

            IssuerAddress = openIdConnectMessage.IssuerAddress;
        }

        /// <summary>
        /// Initializes a new instance of the <see cref="WsFederationMessage"/> class.
        /// </summary>
        /// <param name="parameters">Enumeration of key value pairs.</param>        
        public OpenIdConnectMessage(IEnumerable<KeyValuePair<string, string[]>> parameters)
        {
            if (parameters == null)
            {
                return;
            }

            foreach (KeyValuePair<string, string[]> keyValue in parameters)
            {
                foreach (string strValue in keyValue.Value)
                {
                    if (strValue != null)
                    {
                        SetParameter(keyValue.Key, strValue);
                        break;
                    }
                }
            }
        }

        /// <summary>
        /// Creates an OpenIdConnect message using the current contents of this <see cref="OpenIdConnectMessage"/>.
        /// </summary>
        /// <returns>The uri to use for a redirect.</returns>
        public string CreateIdTokenUrl()
        {
            OpenIdConnectMessage openIdConnectMessage = new OpenIdConnectMessage(this);
            return openIdConnectMessage.BuildRedirectUrl();
        }

        /// <summary>
        /// Creates a query string using the using the current contents of this <see cref="OpenIdConnectMessage"/>.
        /// </summary>
        /// <returns>The uri to use for a redirect.</returns>
        public string CreateLogoutUrl()
        {
            OpenIdConnectMessage openIdConnectMessage = new OpenIdConnectMessage(this);
            return openIdConnectMessage.BuildRedirectUrl();
        }

        /// <summary>
        /// Gets or sets the value for the AuthorizeEndpoint
        /// </summary>
        public string AuthorizeEndpoint { get; set; }

        /// <summary>
        /// Gets or sets 'access_Token'.
        /// </summary>
        [System.Diagnostics.CodeAnalysis.SuppressMessage("Microsoft.Naming", "CA1707", Justification = "Follows protocol names")]
        public string Access_Token
        {
            get { return GetParameter(OpenIdConnectParameterNames.Access_Token); }
            set { SetParameter(OpenIdConnectParameterNames.Access_Token, value); }
        }

        /// <summary>
        /// Gets or sets 'acr_values'.
        /// </summary>
        public string Acr_Values 
        {
            get { return GetParameter(OpenIdConnectParameterNames.Acr_Values); }
            set { SetParameter(OpenIdConnectParameterNames.Acr_Values, value); }
        }

        /// <summary>
        /// Gets or sets 'claims_Locales'.
        /// </summary>
        public string Claims_Locales
        {
            get { return GetParameter(OpenIdConnectParameterNames.Claims_Locales); }
            set { SetParameter(OpenIdConnectParameterNames.Claims_Locales, value); }
        }

        /// <summary>
        /// Gets or sets 'client_assertion'.
        /// </summary>
        public string Client_Assertion
        {
            get { return GetParameter(OpenIdConnectParameterNames.Client_Assertion); }
            set { SetParameter(OpenIdConnectParameterNames.Client_Assertion, value); }
        }

        /// <summary>
        /// Gets or sets 'client_assertion_type'.
        /// </summary>
        public string Client_Assertion_Type
        {
            get { return GetParameter(OpenIdConnectParameterNames.Client_Assertion_Type); }
            set { SetParameter(OpenIdConnectParameterNames.Client_Assertion_Type, value); }
        }

        /// <summary>
        /// Gets or sets 'client_id'.
        /// </summary>
        public string Client_Id
        {
            get { return GetParameter(OpenIdConnectParameterNames.Client_Id); }
            set { SetParameter(OpenIdConnectParameterNames.Client_Id, value); }
        }

        /// <summary>
        /// Gets or sets 'client_secret'.
        /// </summary>
        public string Client_Secret
        {
            get { return GetParameter(OpenIdConnectParameterNames.Client_Secret); }
            set { SetParameter(OpenIdConnectParameterNames.Client_Secret, value); }
        }

        /// <summary>
        /// Gets or sets 'code'.
        /// </summary>
        public string Code
        {
            get { return GetParameter(OpenIdConnectParameterNames.Code); }
            set { SetParameter(OpenIdConnectParameterNames.Code, value); }
        }

        /// <summary>
        /// Gets or sets 'display'.
        /// </summary>
        public string Display
        {
            get { return GetParameter(OpenIdConnectParameterNames.Display); }
            set { SetParameter(OpenIdConnectParameterNames.Display, value); }
        }

        /// <summary>
        /// Gets or sets 'domain_hint'.
        /// </summary>
        public string Domain_Hint
        {
            get { return GetParameter(OpenIdConnectParameterNames.Domain_Hint); }
            set { SetParameter(OpenIdConnectParameterNames.Domain_Hint, value); }
        }

        /// <summary>
        /// Gets or sets 'error'.
        /// </summary>
        public string Error
        {
            get { return GetParameter(OpenIdConnectParameterNames.Error); }
            set { SetParameter(OpenIdConnectParameterNames.Error, value); }
        }

        /// <summary>
        /// Gets or sets 'error_description'.
        /// </summary>
        public string Error_Description
        {
            get { return GetParameter(OpenIdConnectParameterNames.Error_Description); }
            set { SetParameter(OpenIdConnectParameterNames.Error_Description, value); }
        }

        /// <summary>
        /// Gets or sets 'error_uri'.
        /// </summary>
        public string Error_Uri
        {
            get { return GetParameter(OpenIdConnectParameterNames.Error_Uri); }
            set { SetParameter(OpenIdConnectParameterNames.Error_Uri, value); }
        }

        /// <summary>
        /// Gets or sets 'expires_in'.
        /// </summary>
        public string Expires_In
        {
            get { return GetParameter(OpenIdConnectParameterNames.Expires_In); }
            set { SetParameter(OpenIdConnectParameterNames.Expires_In, value); }
        }

        /// <summary>
        /// Gets or sets 'grant_type'.
        /// </summary>
        public string Grant_Type
        {
            get { return GetParameter(OpenIdConnectParameterNames.Grant_Type); }
            set { SetParameter(OpenIdConnectParameterNames.Grant_Type, value); }
        }

        /// <summary>
        /// Gets or sets 'id_token'.
        /// </summary>
        public string Id_Token
        {
            get { return GetParameter(OpenIdConnectParameterNames.Id_Token); }
            set { SetParameter(OpenIdConnectParameterNames.Id_Token, value); }
        }

        /// <summary>
        /// Gets or sets 'id_token_hint'.
        /// </summary>
        public string Id_Token_Hint
        {
            get { return GetParameter(OpenIdConnectParameterNames.Id_Token_Hint); }
            set { SetParameter(OpenIdConnectParameterNames.Id_Token_Hint, value); }
        }

        /// <summary>
        /// Gets or sets 'identity_provider'.
        /// </summary>
        public string Identity_Provider
        {
            get { return GetParameter(OpenIdConnectParameterNames.Identity_Provider); }
            set { SetParameter(OpenIdConnectParameterNames.Identity_Provider, value); }
        }

        /// <summary>
        /// Gets or sets 'iss'.
        /// </summary>
        public string Iss
        {
            get { return GetParameter(OpenIdConnectParameterNames.Iss); }
            set { SetParameter(OpenIdConnectParameterNames.Iss, value); }
        }

        /// <summary>
        /// Gets or sets 'login_hint'.
        /// </summary>
        [property: System.Diagnostics.CodeAnalysis.SuppressMessage("Microsoft.Naming", "CA1707")]  
        public string Login_Hint
        {
            get { return GetParameter(OpenIdConnectParameterNames.Login_Hint); }
            set { SetParameter(OpenIdConnectParameterNames.Login_Hint, value); }
        }

        /// <summary>
        /// Gets or sets 'max_age'.
        /// </summary>
        public string Max_Age
        {
            get { return GetParameter(OpenIdConnectParameterNames.Max_Age); }
            set { SetParameter(OpenIdConnectParameterNames.Max_Age, value); }
        }

        /// <summary>
        /// Gets or sets 'nonce'.
        /// </summary>
        public string Nonce
        {
            get { return GetParameter(OpenIdConnectParameterNames.Nonce); }
            set { SetParameter(OpenIdConnectParameterNames.Nonce, value); }
        }

        /// <summary>
        /// Gets or sets 'password'.
        /// </summary>
        public string Password
        {
            get { return GetParameter(OpenIdConnectParameterNames.Password); }
            set { SetParameter(OpenIdConnectParameterNames.Password, value); }
        }

        /// <summary>
        /// Gets or sets 'post_logout_redirect_uri'.
        /// </summary>
        public string Post_Logout_Redirect_Uri
        {
            get { return GetParameter(OpenIdConnectParameterNames.Post_Logout_Redirect_Uri); }
            set { SetParameter(OpenIdConnectParameterNames.Post_Logout_Redirect_Uri, value); }
        }

        /// <summary>
        /// Gets or sets 'prompt'.
        /// </summary>
        public string Prompt
        {
            get { return GetParameter(OpenIdConnectParameterNames.Prompt); }
            set { SetParameter(OpenIdConnectParameterNames.Prompt, value); }
        }

        /// <summary>
        /// Gets or sets 'redirect_uri'.
        /// </summary>
        public string Redirect_Uri
        {
            get { return GetParameter(OpenIdConnectParameterNames.Redirect_Uri); }
            set { SetParameter(OpenIdConnectParameterNames.Redirect_Uri, value); }
        }

        /// <summary>
        /// Gets or sets 'request_uri'.
        /// </summary>
        public string Request_Uri
        {
            get { return GetParameter(OpenIdConnectParameterNames.Request_Uri); }
            set { SetParameter(OpenIdConnectParameterNames.Request_Uri, value); }
        }

        /// <summary>
        /// Gets or sets 'response_mode'.
        /// </summary>
        public string Response_Mode
        {
            get { return GetParameter(OpenIdConnectParameterNames.Response_Mode); }
            set { SetParameter(OpenIdConnectParameterNames.Response_Mode, value); }
        }

        /// <summary>
        /// Gets or sets 'response_type'.
        /// </summary>
        public string Response_Type
        {
            get { return GetParameter(OpenIdConnectParameterNames.Response_Type); }
            set { SetParameter(OpenIdConnectParameterNames.Response_Type, value); }
        }

        /// <summary>
        /// Gets or sets 'resource'
        /// </summary>
        public string Resource
        {
            get { return GetParameter(OpenIdConnectParameterNames.Resource); }
            set { SetParameter(OpenIdConnectParameterNames.Resource, value); }
        }
        
        /// <summary>
        /// Gets or sets 'scope'.
        /// </summary>
        public string Scope
        {
            get { return GetParameter(OpenIdConnectParameterNames.Scope); }
            set { SetParameter(OpenIdConnectParameterNames.Scope, value); }
        }

        /// <summary>
        /// Gets or sets 'session_state'.
        /// </summary>
        public string Session_State
        {
            get { return GetParameter(OpenIdConnectParameterNames.Session_State); }
            set { SetParameter(OpenIdConnectParameterNames.Session_State, value); }
        }

        /// <summary>
        /// Gets or sets 'state'.
        /// </summary>
        public string State
        {
            get { return GetParameter(OpenIdConnectParameterNames.State); }
            set { SetParameter(OpenIdConnectParameterNames.State, value); }
        }

        /// <summary>
        /// Gets or sets 'target_link_uri'.
        /// </summary>
        public string Target_Link_Uri
        {
            get { return GetParameter(OpenIdConnectParameterNames.Target_Link_Uri); }
            set { SetParameter(OpenIdConnectParameterNames.Target_Link_Uri, value); }
        }

        /// <summary>
        /// Gets or sets 'token'.
        /// </summary>
        public string Token
        {
            get { return GetParameter(OpenIdConnectParameterNames.Token); }
            set { SetParameter(OpenIdConnectParameterNames.Token, value); }
        }

        /// <summary>
        /// Gets or sets the value for the token endpoint.
        /// </summary>
        public string TokenEndpoint { get; set; }

        /// <summary>
        /// Gets or sets 'token_type'.
        /// </summary>
        public string Token_Type
        {
            get { return GetParameter(OpenIdConnectParameterNames.Token_Type); }
            set { SetParameter(OpenIdConnectParameterNames.Token_Type, value); }
        }

        /// <summary>
        /// Gets or sets 'ui_locales'.
        /// </summary>
        public string Ui_Locales
        {
            get { return GetParameter(OpenIdConnectParameterNames.Ui_Locales); }
            set { SetParameter(OpenIdConnectParameterNames.Ui_Locales, value); }
        }

        /// <summary>
        /// Gets or sets 'user_id'.
        /// </summary>
        public string User_Id
        {
            get { return GetParameter(OpenIdConnectParameterNames.User_Id); }
            set { SetParameter(OpenIdConnectParameterNames.User_Id, value); }
        }
        
        /// <summary>
        /// Gets or sets 'username'.
        /// </summary>
        public string Username
        {
            get { return GetParameter(OpenIdConnectParameterNames.Username); }
            set { SetParameter(OpenIdConnectParameterNames.Username, value); }
        }
    }
}