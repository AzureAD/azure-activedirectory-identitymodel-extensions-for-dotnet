// Copyright (c) Microsoft Corporation. All rights reserved.
// Licensed under the MIT License.

using System;
using System.Collections.Generic;
using System.Collections.Specialized;
using System.Reflection;
using System.Text;
using System.Text.Json;
using Microsoft.IdentityModel.Logging;
using JsonPrimitives = Microsoft.IdentityModel.Tokens.Json.JsonSerializerPrimitives;

namespace Microsoft.IdentityModel.Protocols.OpenIdConnect
{
    /// <summary>
    /// Provides access to common OpenID Connect parameters.
    /// </summary>
    public class OpenIdConnectMessage : AuthenticationProtocolMessage
    {
        internal const string ClassName = "Microsoft.IdentityModel.Protocols.OpenIdConnect.OpenIdConnectMessage";

        /// <summary>
        /// Initializes a new instance of the <see cref="OpenIdConnectMessage"/> class.
        /// </summary>
        public OpenIdConnectMessage() { }

        /// <summary>
        /// Initializes a new instance of <see cref="OpenIdConnectMessage"/> class with a json string.
        /// </summary>
        public OpenIdConnectMessage(string json)
        {
            if (string.IsNullOrEmpty(json))
                throw LogHelper.LogArgumentNullException("json");

            try
            {
                SetJsonParameters(json);
            }
            catch
            {
                throw LogHelper.LogExceptionMessage(new ArgumentException(LogHelper.FormatInvariant(LogMessages.IDX21106, json)));
            }
        }

        /// <summary>
        /// Initializes a new instance of the <see cref="OpenIdConnectMessage"/> class.
        /// </summary>
        /// <param name="other"> an <see cref="OpenIdConnectMessage"/> to copy.</param>
        /// <exception cref="ArgumentNullException">Thrown if <paramref name="other"/> is null.</exception>
        protected OpenIdConnectMessage(OpenIdConnectMessage other)
        {
            if (other == null)
                throw LogHelper.LogArgumentNullException("other");

            foreach (KeyValuePair<string, string> keyValue in other.Parameters)
            {
                SetParameter(keyValue.Key, keyValue.Value);
            }

            AuthorizationEndpoint = other.AuthorizationEndpoint;
            IssuerAddress = other.IssuerAddress;
            RequestType = other.RequestType;
            TokenEndpoint = other.TokenEndpoint;
            EnableTelemetryParameters = other.EnableTelemetryParameters;
        }

        /// <summary>
        /// Initializes a new instance of the <see cref="OpenIdConnectMessage"/> class.
        /// </summary>
        /// <param name="nameValueCollection">Collection of key value pairs.</param>
        public OpenIdConnectMessage(NameValueCollection nameValueCollection)
        {
            if (nameValueCollection == null)
                throw LogHelper.LogArgumentNullException("nameValueCollection");

            foreach (var key in nameValueCollection.AllKeys)
            {
                if (key != null)
                {
                    SetParameter(key, nameValueCollection[key]);
                }
            }
        }

        /// <summary>
        /// Initializes a new instance of the <see cref="OpenIdConnectMessage"/> class.
        /// </summary>
        /// <param name="parameters">Enumeration of key value pairs.</param>
        public OpenIdConnectMessage(IEnumerable<KeyValuePair<string, string[]>> parameters)
        {
            if (parameters == null)
                throw LogHelper.LogArgumentNullException("parameters");

            foreach (KeyValuePair<string, string[]> keyValue in parameters)
            {
                if (keyValue.Value != null && !string.IsNullOrWhiteSpace(keyValue.Key))
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
        }

        private void SetJsonParameters(string json)
        {
            Utf8JsonReader reader = new(Encoding.UTF8.GetBytes(json).AsSpan());
            if (!JsonPrimitives.IsReaderAtTokenType(ref reader, JsonTokenType.StartObject, true))
                throw LogHelper.LogExceptionMessage(
                    new JsonException(
                        LogHelper.FormatInvariant(
                        Tokens.LogMessages.IDX11023,
                        LogHelper.MarkAsNonPII("JsonTokenType.StartObject"),
                        LogHelper.MarkAsNonPII(reader.TokenType),
                        LogHelper.MarkAsNonPII(ClassName),
                        LogHelper.MarkAsNonPII(reader.TokenStartIndex),
                        LogHelper.MarkAsNonPII(reader.CurrentDepth),
                        LogHelper.MarkAsNonPII(reader.BytesConsumed))));

            while(true)
            {
                // propertyValue is set to match 6.x
                if (reader.TokenType == JsonTokenType.PropertyName)
                {
                    string propertyName = JsonPrimitives.ReadPropertyName(ref reader, ClassName, true);
                    string propertyValue = null;
                    if (reader.TokenType == JsonTokenType.String)
                        propertyValue = JsonPrimitives.ReadString(ref reader, propertyName, ClassName);
                    else if (reader.TokenType == JsonTokenType.Number)
                        propertyValue = (JsonPrimitives.ReadNumber(ref reader)).ToString();
                    else if ((reader.TokenType == JsonTokenType.True) || (reader.TokenType == JsonTokenType.False))
                        propertyValue = JsonPrimitives.ReadBoolean(ref reader, propertyName, ClassName, false).ToString();
                    else if (reader.TokenType == JsonTokenType.Null)
                    {
                        propertyValue = "";
                        reader.Read();
                    }
                    else if (reader.TokenType == JsonTokenType.StartArray)
                        propertyValue = JsonPrimitives.ReadJsonElement(ref reader).GetRawText();
                    else if (reader.TokenType == JsonTokenType.StartObject)
                        propertyValue = JsonPrimitives.ReadJsonElement(ref reader).GetRawText();

                    SetParameter(propertyName, propertyValue);
                }
                // We read a JsonTokenType.StartObject above, exiting and positioning reader at next token.
                else if (JsonPrimitives.IsReaderAtTokenType(ref reader, JsonTokenType.EndObject, true))
                    break;
                else if (!reader.Read())
                    break;
            }
        }

        /// <summary>
        /// Returns a new instance of <see cref="OpenIdConnectMessage"/> with values copied from this object.
        /// </summary>
        /// <returns>A new <see cref="OpenIdConnectMessage"/> object copied from this object</returns>
        /// <remarks>This is a shallow Clone.</remarks>
        public virtual OpenIdConnectMessage Clone()
        {
            return new OpenIdConnectMessage(this);
        }

        /// <summary>
        /// Creates an OpenIdConnect message using the current contents of this <see cref="OpenIdConnectMessage"/>.
        /// </summary>
        /// <returns>The uri to use for a redirect.</returns>
        public virtual string CreateAuthenticationRequestUrl()
        {
            OpenIdConnectMessage openIdConnectMessage = Clone();
            openIdConnectMessage.RequestType = OpenIdConnectRequestType.Authentication;
            EnsureTelemetryValues(openIdConnectMessage);
            return openIdConnectMessage.BuildRedirectUrl();
        }

        /// <summary>
        /// Creates a query string using the current contents of this <see cref="OpenIdConnectMessage"/>.
        /// </summary>
        /// <returns>The uri to use for a redirect.</returns>
        public virtual string CreateLogoutRequestUrl()
        {
            OpenIdConnectMessage openIdConnectMessage = Clone();
            openIdConnectMessage.RequestType = OpenIdConnectRequestType.Logout;
            EnsureTelemetryValues(openIdConnectMessage);
            return openIdConnectMessage.BuildRedirectUrl();
        }

        /// <summary>
        /// Adds telemetry values to the message parameters.
        /// </summary>
        private void EnsureTelemetryValues(OpenIdConnectMessage clonedMessage)
        {
            if (this.EnableTelemetryParameters)
            {
                clonedMessage.SetParameter(OpenIdConnectParameterNames.SkuTelemetry, SkuTelemetryValue);
                clonedMessage.SetParameter(OpenIdConnectParameterNames.VersionTelemetry, typeof(OpenIdConnectMessage).GetTypeInfo().Assembly.GetName().Version.ToString());
            }
        }

        /// <summary>
        /// Gets or sets the value for the AuthorizationEndpoint
        /// </summary>
        public string AuthorizationEndpoint { get; set; }

        /// <summary>
        /// Gets or sets 'access_Token'.
        /// </summary>
        [System.Diagnostics.CodeAnalysis.SuppressMessage("Microsoft.Naming", "CA1707", Justification = "Follows protocol names")]
        public string AccessToken
        {
            get { return GetParameter(OpenIdConnectParameterNames.AccessToken); }
            set { SetParameter(OpenIdConnectParameterNames.AccessToken, value); }
        }

        /// <summary>
        /// Gets or sets 'acr_values'.
        /// </summary>
        public string AcrValues 
        {
            get { return GetParameter(OpenIdConnectParameterNames.AcrValues); }
            set { SetParameter(OpenIdConnectParameterNames.AcrValues, value); }
        }

        /// <summary>
        /// Gets or sets 'claims_Locales'.
        /// </summary>
        public string ClaimsLocales
        {
            get { return GetParameter(OpenIdConnectParameterNames.ClaimsLocales); }
            set { SetParameter(OpenIdConnectParameterNames.ClaimsLocales, value); }
        }

        /// <summary>
        /// Gets or sets 'client_assertion'.
        /// </summary>
        public string ClientAssertion
        {
            get { return GetParameter(OpenIdConnectParameterNames.ClientAssertion); }
            set { SetParameter(OpenIdConnectParameterNames.ClientAssertion, value); }
        }

        /// <summary>
        /// Gets or sets 'client_assertion_type'.
        /// </summary>
        public string ClientAssertionType
        {
            get { return GetParameter(OpenIdConnectParameterNames.ClientAssertionType); }
            set { SetParameter(OpenIdConnectParameterNames.ClientAssertionType, value); }
        }

        /// <summary>
        /// Gets or sets 'client_id'.
        /// </summary>
        public string ClientId
        {
            get { return GetParameter(OpenIdConnectParameterNames.ClientId); }
            set { SetParameter(OpenIdConnectParameterNames.ClientId, value); }
        }

        /// <summary>
        /// Gets or sets 'client_secret'.
        /// </summary>
        public string ClientSecret
        {
            get { return GetParameter(OpenIdConnectParameterNames.ClientSecret); }
            set { SetParameter(OpenIdConnectParameterNames.ClientSecret, value); }
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
        public string DomainHint
        {
            get { return GetParameter(OpenIdConnectParameterNames.DomainHint); }
            set { SetParameter(OpenIdConnectParameterNames.DomainHint, value); }
        }

        /// <summary>
        /// Gets or sets whether parameters for the library and version are sent on the query string for this <see cref="OpenIdConnectMessage"/> instance. 
        /// This value is set to the value of EnableTelemetryParametersByDefault at message creation time.
        /// </summary>
        public bool EnableTelemetryParameters { get; set; } = EnableTelemetryParametersByDefault;


        /// <summary>
        /// Gets or sets whether parameters for the library and version are sent on the query string for all instances of <see cref="OpenIdConnectMessage"/>. 
        /// </summary>
        public static bool EnableTelemetryParametersByDefault { get; set; } = true;

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
        public string ErrorDescription
        {
            get { return GetParameter(OpenIdConnectParameterNames.ErrorDescription); }
            set { SetParameter(OpenIdConnectParameterNames.ErrorDescription, value); }
        }

        /// <summary>
        /// Gets or sets 'error_uri'.
        /// </summary>
        public string ErrorUri
        {
            get { return GetParameter(OpenIdConnectParameterNames.ErrorUri); }
            set { SetParameter(OpenIdConnectParameterNames.ErrorUri, value); }
        }

        /// <summary>
        /// Gets or sets 'expires_in'.
        /// </summary>
        public string ExpiresIn
        {
            get { return GetParameter(OpenIdConnectParameterNames.ExpiresIn); }
            set { SetParameter(OpenIdConnectParameterNames.ExpiresIn, value); }
        }

        /// <summary>
        /// Gets or sets 'grant_type'.
        /// </summary>
        public string GrantType
        {
            get { return GetParameter(OpenIdConnectParameterNames.GrantType); }
            set { SetParameter(OpenIdConnectParameterNames.GrantType, value); }
        }

        /// <summary>
        /// Gets or sets 'id_token'.
        /// </summary>
        public string IdToken
        {
            get { return GetParameter(OpenIdConnectParameterNames.IdToken); }
            set { SetParameter(OpenIdConnectParameterNames.IdToken, value); }
        }

        /// <summary>
        /// Gets or sets 'id_token_hint'.
        /// </summary>
        public string IdTokenHint
        {
            get { return GetParameter(OpenIdConnectParameterNames.IdTokenHint); }
            set { SetParameter(OpenIdConnectParameterNames.IdTokenHint, value); }
        }

        /// <summary>
        /// Gets or sets 'identity_provider'.
        /// </summary>
        public string IdentityProvider
        {
            get { return GetParameter(OpenIdConnectParameterNames.IdentityProvider); }
            set { SetParameter(OpenIdConnectParameterNames.IdentityProvider, value); }
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
        public string LoginHint
        {
            get { return GetParameter(OpenIdConnectParameterNames.LoginHint); }
            set { SetParameter(OpenIdConnectParameterNames.LoginHint, value); }
        }

        /// <summary>
        /// Gets or sets 'max_age'.
        /// </summary>
        public string MaxAge
        {
            get { return GetParameter(OpenIdConnectParameterNames.MaxAge); }
            set { SetParameter(OpenIdConnectParameterNames.MaxAge, value); }
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
        public string PostLogoutRedirectUri
        {
            get { return GetParameter(OpenIdConnectParameterNames.PostLogoutRedirectUri); }
            set { SetParameter(OpenIdConnectParameterNames.PostLogoutRedirectUri, value); }
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
        public string RedirectUri
        {
            get { return GetParameter(OpenIdConnectParameterNames.RedirectUri); }
            set { SetParameter(OpenIdConnectParameterNames.RedirectUri, value); }
        }

        /// <summary>
        /// Gets or sets 'refresh_token'.
        /// </summary>
        public string RefreshToken
        {
            get { return GetParameter(OpenIdConnectParameterNames.RefreshToken); }
            set { SetParameter(OpenIdConnectParameterNames.RefreshToken, value); }
        }

        /// <summary>
        /// Gets or set the request type for this message
        /// </summary>
        /// <remarks>This is helpful when sending different messages through a common routine, when extra parameters need to be set or checked.</remarks>
        public OpenIdConnectRequestType RequestType
        {
            get;
            set;
        }

        /// <summary>
        /// Gets or sets 'request_uri'.
        /// </summary>
        public string RequestUri
        {
            get { return GetParameter(OpenIdConnectParameterNames.RequestUri); }
            set { SetParameter(OpenIdConnectParameterNames.RequestUri, value); }
        }

        /// <summary>
        /// Gets or sets 'response_mode'.
        /// </summary>
        public string ResponseMode
        {
            get { return GetParameter(OpenIdConnectParameterNames.ResponseMode); }
            set { SetParameter(OpenIdConnectParameterNames.ResponseMode, value); }
        }

        /// <summary>
        /// Gets or sets 'response_type'.
        /// </summary>
        public string ResponseType
        {
            get { return GetParameter(OpenIdConnectParameterNames.ResponseType); }
            set { SetParameter(OpenIdConnectParameterNames.ResponseType, value); }
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
        public string SessionState
        {
            get { return GetParameter(OpenIdConnectParameterNames.SessionState); }
            set { SetParameter(OpenIdConnectParameterNames.SessionState, value); }
        }

        /// <summary>
        /// Gets or sets 'sid'.
        /// </summary>
        public string Sid
        {
            get { return GetParameter(OpenIdConnectParameterNames.Sid); }
            set { SetParameter(OpenIdConnectParameterNames.Sid, value); }
        }

        /// <summary>
        /// Gets the string that is sent as telemetry data in an OpenIdConnectMessage.
        /// </summary>
        public string SkuTelemetryValue { get; set; } = IdentityModelTelemetryUtil.ClientSku;

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
        public string TargetLinkUri
        {
            get { return GetParameter(OpenIdConnectParameterNames.TargetLinkUri); }
            set { SetParameter(OpenIdConnectParameterNames.TargetLinkUri, value); }
        }

        /// <summary>
        /// Gets or sets the value for the token endpoint.
        /// </summary>
        public string TokenEndpoint { get; set; }

        /// <summary>
        /// Gets or sets 'token_type'.
        /// </summary>
        public string TokenType
        {
            get { return GetParameter(OpenIdConnectParameterNames.TokenType); }
            set { SetParameter(OpenIdConnectParameterNames.TokenType, value); }
        }

        /// <summary>
        /// Gets or sets 'ui_locales'.
        /// </summary>
        public string UiLocales
        {
            get { return GetParameter(OpenIdConnectParameterNames.UiLocales); }
            set { SetParameter(OpenIdConnectParameterNames.UiLocales, value); }
        }

        /// <summary>
        /// Gets or sets 'user_id'.
        /// </summary>
        public string UserId
        {
            get { return GetParameter(OpenIdConnectParameterNames.UserId); }
            set { SetParameter(OpenIdConnectParameterNames.UserId, value); }
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
