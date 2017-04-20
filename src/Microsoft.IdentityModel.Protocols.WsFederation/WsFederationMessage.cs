//------------------------------------------------------------------------------
//
// Copyright (c) Microsoft Corporation.
// All rights reserved.
//
// This code is licensed under the MIT License.
//
// Permission is hereby granted, free of charge, to any person obtaining a copy
// of this software and associated documentation files(the "Software"), to deal
// in the Software without restriction, including without limitation the rights
// to use, copy, modify, merge, publish, distribute, sublicense, and / or sell
// copies of the Software, and to permit persons to whom the Software is
// furnished to do so, subject to the following conditions :
//
// The above copyright notice and this permission notice shall be included in
// all copies or substantial portions of the Software.
//
// THE SOFTWARE IS PROVIDED "AS IS", WITHOUT WARRANTY OF ANY KIND, EXPRESS OR
// IMPLIED, INCLUDING BUT NOT LIMITED TO THE WARRANTIES OF MERCHANTABILITY,
// FITNESS FOR A PARTICULAR PURPOSE AND NONINFRINGEMENT.IN NO EVENT SHALL THE
// AUTHORS OR COPYRIGHT HOLDERS BE LIABLE FOR ANY CLAIM, DAMAGES OR OTHER
// LIABILITY, WHETHER IN AN ACTION OF CONTRACT, TORT OR OTHERWISE, ARISING FROM,
// OUT OF OR IN CONNECTION WITH THE SOFTWARE OR THE USE OR OTHER DEALINGS IN
// THE SOFTWARE.
//
//------------------------------------------------------------------------------

using System;
using System.Collections.Generic;
using System.Globalization;
using System.IO;
using System.Xml;
using Microsoft.IdentityModel.Logging;

namespace Microsoft.IdentityModel.Protocols.WsFederation
{
    /// <summary>
    /// Provides access to common WsFederation message parameters.
    /// </summary>
    [type: System.Diagnostics.CodeAnalysis.SuppressMessage("Microsoft.Naming", "CA1704")]   
    public class WsFederationMessage : AuthenticationProtocolMessage
    {
        /// <summary>
        /// Creates a <see cref="WsFederationMessage"/> from the contents of a query string.
        /// </summary>
        /// <param name="queryString"> query string to extract parameters.</param>
        /// <returns>An instance of <see cref="WsFederationMessage"/>.</returns>
        /// <remarks>If 'queryString' is null or whitespace, a default <see cref="WsFederationMessage"/> is returned. Parameters are parsed from <see cref="Uri.Query"/>.</remarks>
        public static WsFederationMessage FromQueryString(string queryString)
        {
            IdentityModelEventSource.Logger.WriteVerbose(string.Format(CultureInfo.InvariantCulture, LogMessages.IDX10900, queryString));
            WsFederationMessage wsFederationMessage = new WsFederationMessage();
            if (!string.IsNullOrWhiteSpace(queryString))
            {
                var result = QueryHelper.ParseQuery(queryString);

                foreach(var keyValuePair in result)
                {
                    foreach(var value in keyValuePair.Value)
                    {
                        wsFederationMessage.SetParameter(keyValuePair.Key, value);
                    }
                }
            } 

            return wsFederationMessage;
        }

        /// <summary>
        /// Creates a <see cref="WsFederationMessage"/> from the contents of a <see cref="Uri"/>.
        /// </summary>
        /// <param name="uri"> uri string to extract parameters.</param>
        /// <returns>An instance of <see cref="WsFederationMessage"/>.</returns>
        /// <remarks><see cref="WsFederationMessage"/>.IssuerAddress is NOT set/>. Parameters are parsed from <see cref="Uri.Query"/>.</remarks>
        public static WsFederationMessage FromUri(Uri uri)
        {
            IdentityModelEventSource.Logger.WriteVerbose(string.Format(CultureInfo.InvariantCulture, LogMessages.IDX10901, uri.ToString()));
            if (uri != null && uri.Query.Length > 1)
            {
                return WsFederationMessage.FromQueryString(uri.Query.Substring(1));
            }

            return new WsFederationMessage();
        }

        /// <summary>
        /// Initializes a new instance of the <see cref="WsFederationMessage"/> class.
        /// </summary>
        public WsFederationMessage(){}
        
        /// <summary>
        /// Initializes a new instance of the <see cref="WsFederationMessage"/> class.
        /// </summary>
        /// <param name="wsFederationMessage"> message to copy.</param>        
        public WsFederationMessage(WsFederationMessage wsFederationMessage)
        {
            if (wsFederationMessage == null)
            {
                IdentityModelEventSource.Logger.WriteWarning(string.Format(CultureInfo.InvariantCulture, LogMessages.IDX10000, "wsfederationMessage"));
                return;
            }

            foreach (KeyValuePair<string, string> keyValue in wsFederationMessage.Parameters)
            {
                SetParameter(keyValue.Key, keyValue.Value);
            }

            IssuerAddress = wsFederationMessage.IssuerAddress;
        }

        /// <summary>
        /// Initializes a new instance of the <see cref="WsFederationMessage"/> class.
        /// </summary>
        /// <param name="parameters">Enumeration of key value pairs.</param>        
        public WsFederationMessage(IEnumerable<KeyValuePair<string, string[]>> parameters)
        {
            if (parameters == null)
            {
                IdentityModelEventSource.Logger.WriteWarning(string.Format(CultureInfo.InvariantCulture, LogMessages.IDX10000, "parameters"));
                return;
            }

            foreach (KeyValuePair<string, string[]> keyValue in parameters)
            {
                foreach (string strValue in keyValue.Value)
                {
                    SetParameter(keyValue.Key, strValue);
                }
            }
        }

        /// <summary>
        /// Creates a 'wsignin1.0' message using the current contents of this <see cref="WsFederationMessage"/>.
        /// </summary>
        /// <returns>The uri to use for a redirect.</returns>

        public string CreateSignInUrl()
        {
            WsFederationMessage wsFederationMessage = new WsFederationMessage(this);
            wsFederationMessage.Wa = WsFederationConstants.WsFederationActions.SignIn;
            return wsFederationMessage.BuildRedirectUrl();
        }

        /// <summary>
        /// Creates a 'wsignout1.0' message using the current contents of this <see cref="WsFederationMessage"/>.
        /// </summary>
        /// <returns>The uri to use for a redirect.</returns>
        public string CreateSignOutUrl()
        {
            WsFederationMessage wsFederationMessage = new WsFederationMessage(this);
            wsFederationMessage.Wa = WsFederationConstants.WsFederationActions.SignOut;
            return wsFederationMessage.BuildRedirectUrl();
        }
        
        /// <summary>
        /// Reads the 'wresult' and returns the embeded security token.
        /// </summary>
        /// <returns>the 'SecurityToken'.</returns>
        public virtual string GetToken()
        {
            if (Wresult == null)
            {
                IdentityModelEventSource.Logger.WriteWarning(string.Format(CultureInfo.InvariantCulture, LogMessages.IDX10000, "wresult"));
                return null;
            }

            using (StringReader sr = new StringReader(Wresult))
            {
                XmlReader xmlReader = XmlReader.Create(sr);
                xmlReader.MoveToContent();

                // TODO need serializer to get token from response.
                //WSTrustResponseSerializer serializer = new WSTrust13ResponseSerializer();
                //if (serializer.CanRead(xmlReader))
                //{
                //    RequestSecurityTokenResponse response = serializer.ReadXml(xmlReader, new WSTrustSerializationContext());
                //    return response.RequestedSecurityToken.SecurityTokenXml.OuterXml;
                //}

                //serializer = new WSTrustFeb2005ResponseSerializer();
                //if (serializer.CanRead(xmlReader))
                //{
                //    RequestSecurityTokenResponse response = serializer.ReadXml(xmlReader, new WSTrustSerializationContext());
                //    return response.RequestedSecurityToken.SecurityTokenXml.OuterXml;
                //}
            }

            return null;
        }

        /// <summary>
        /// Gets a boolean representating if the <see cref="WsFederationMessage"/> is a 'sign-in-message'.
        /// </summary>
        public bool IsSignInMessage
        {
            get
            {
                return Wa == WsFederationConstants.WsFederationActions.SignIn;
            }
        }
        
        /// <summary>
        /// Gets a boolean representating if the <see cref="WsFederationMessage"/> is a 'sign-out-message'.
        /// </summary>
        public bool IsSignOutMessage
        {
            get
            {
                return Wa == WsFederationConstants.WsFederationActions.SignOut;
            }
        }

        /// <summary>
        /// Gets or sets 'wa'.
        /// </summary>
        [property: System.Diagnostics.CodeAnalysis.SuppressMessage("Microsoft.Naming", "CA1709:IdentifiersShouldBeCasedCorrectly", MessageId = "Wa")]
        [property: System.Diagnostics.CodeAnalysis.SuppressMessage("Microsoft.Naming", "CA1704")]
        public string Wa 
        { 
            get { return GetParameter(WsFederationConstants.WsFederationParameterNames.Wa); }
            set { SetParameter(WsFederationConstants.WsFederationParameterNames.Wa, value); }
        }

        /// <summary>
        /// Gets or sets 'wattr'.
        /// </summary>
        [property: System.Diagnostics.CodeAnalysis.SuppressMessage("Microsoft.Naming", "CA1704")]
        public string Wattr
        {
            get { return GetParameter(WsFederationConstants.WsFederationParameterNames.Wattr); }
            set { SetParameter(WsFederationConstants.WsFederationParameterNames.Wattr, value); }
        }

        /// <summary>
        /// Gets or sets 'wattrptr'.
        /// </summary>
        [property: System.Diagnostics.CodeAnalysis.SuppressMessage("Microsoft.Naming", "CA1704")]
        public string Wattrptr
        {
            get { return GetParameter(WsFederationConstants.WsFederationParameterNames.Wattrptr); }
            set { SetParameter(WsFederationConstants.WsFederationParameterNames.Wattrptr, value); }
        }

        /// <summary>
        /// Gets or sets 'wauth'.
        /// </summary>
        [property: System.Diagnostics.CodeAnalysis.SuppressMessage("Microsoft.Naming", "CA1704")]
        public string Wauth
        {
            get { return GetParameter(WsFederationConstants.WsFederationParameterNames.Wauth); }
            set { SetParameter(WsFederationConstants.WsFederationParameterNames.Wauth, value); }
        }

        /// <summary>
        /// Gets or sets 'Wct'.
        /// </summary>
        [property: System.Diagnostics.CodeAnalysis.SuppressMessage("Microsoft.Naming", "CA1704")]
        public string Wct
        {
            get { return GetParameter(WsFederationConstants.WsFederationParameterNames.Wct); }
            set { SetParameter(WsFederationConstants.WsFederationParameterNames.Wct, value); }
        }

        /// <summary>
        /// Gets or sets 'wa'.
        /// </summary>
        [property: System.Diagnostics.CodeAnalysis.SuppressMessage("Microsoft.Naming", "CA1704")]        
        public string Wctx
        {
            get { return GetParameter(WsFederationConstants.WsFederationParameterNames.Wctx); }
            set { SetParameter(WsFederationConstants.WsFederationParameterNames.Wctx, value); }
        }

        /// <summary>
        /// Gets or sets 'Wencoding'.
        /// </summary>
        [property: System.Diagnostics.CodeAnalysis.SuppressMessage("Microsoft.Naming", "CA1704")]
        public string Wencoding
        {
            get { return GetParameter(WsFederationConstants.WsFederationParameterNames.Wencoding); }
            set { SetParameter(WsFederationConstants.WsFederationParameterNames.Wencoding, value); }
        }

        /// <summary>
        /// Gets or sets 'wfed'.
        /// </summary>
        [property: System.Diagnostics.CodeAnalysis.SuppressMessage("Microsoft.Naming", "CA1704")]
        public string Wfed
        {
            get { return GetParameter(WsFederationConstants.WsFederationParameterNames.Wfed); }
            set { SetParameter(WsFederationConstants.WsFederationParameterNames.Wfed, value); }
        }

        /// <summary>
        /// Gets or sets 'wfresh'.
        /// </summary>
        [property: System.Diagnostics.CodeAnalysis.SuppressMessage("Microsoft.Naming", "CA1704")]
        public string Wfresh
        {
            get { return GetParameter(WsFederationConstants.WsFederationParameterNames.Wfresh); }
            set { SetParameter(WsFederationConstants.WsFederationParameterNames.Wfresh, value); }
        }

        /// <summary>
        /// Gets or sets 'whr'.
        /// </summary>
        [property: System.Diagnostics.CodeAnalysis.SuppressMessage("Microsoft.Naming", "CA1704")]
        public string Whr
        {
            get { return GetParameter(WsFederationConstants.WsFederationParameterNames.Whr); }
            set { SetParameter(WsFederationConstants.WsFederationParameterNames.Whr, value); }
        }

        /// <summary>
        /// Gets or sets 'wp'.
        /// </summary>
        [property: System.Diagnostics.CodeAnalysis.SuppressMessage("Microsoft.Naming", "CA1704")]
        [property: System.Diagnostics.CodeAnalysis.SuppressMessage("Microsoft.Naming", "CA1709")]
        public string Wp
        {
            get { return GetParameter(WsFederationConstants.WsFederationParameterNames.Wp); }
            set { SetParameter(WsFederationConstants.WsFederationParameterNames.Wp, value); }
        }

        /// <summary>
        /// Gets or sets 'wpseudo'.
        /// </summary>
        [property: System.Diagnostics.CodeAnalysis.SuppressMessage("Microsoft.Naming", "CA1704")]
        public string Wpseudo
        {
            get { return GetParameter(WsFederationConstants.WsFederationParameterNames.Wpseudo); }
            set { SetParameter(WsFederationConstants.WsFederationParameterNames.Wpseudo, value); }
        }

        /// <summary>
        /// Gets or sets 'wpseudoptr'.
        /// </summary>
        [property: System.Diagnostics.CodeAnalysis.SuppressMessage("Microsoft.Naming", "CA1704")]
        public string Wpseudoptr
        {
            get { return GetParameter(WsFederationConstants.WsFederationParameterNames.Wpseudoptr); }
            set { SetParameter(WsFederationConstants.WsFederationParameterNames.Wpseudoptr, value); }
        }

        /// <summary>
        /// Gets or sets 'wreply'.
        /// </summary>
        [property: System.Diagnostics.CodeAnalysis.SuppressMessage("Microsoft.Naming", "CA1704")]
        public string Wreply
        {
            get { return GetParameter(WsFederationConstants.WsFederationParameterNames.Wreply); }
            set { SetParameter(WsFederationConstants.WsFederationParameterNames.Wreply, value); }
        }

        /// <summary>
        /// Gets or sets 'wreq'.
        /// </summary>
        [property: System.Diagnostics.CodeAnalysis.SuppressMessage("Microsoft.Naming", "CA1704")]        
        public string Wreq
        {
            get { return GetParameter(WsFederationConstants.WsFederationParameterNames.Wreq); }
            set { SetParameter(WsFederationConstants.WsFederationParameterNames.Wreq, value); }
        }

        /// <summary>
        /// Gets or sets 'wreqptr'.
        /// </summary>
        [property: System.Diagnostics.CodeAnalysis.SuppressMessage("Microsoft.Naming", "CA1704")]        
        public string Wreqptr
        {
            get { return GetParameter(WsFederationConstants.WsFederationParameterNames.Wreqptr); }
            set { SetParameter(WsFederationConstants.WsFederationParameterNames.Wreqptr, value); }
        }

        /// <summary>
        /// Gets or sets 'wres'.
        /// </summary>
        [property: System.Diagnostics.CodeAnalysis.SuppressMessage("Microsoft.Naming", "CA1704")]        
        public string Wres
        {
            get { return GetParameter(WsFederationConstants.WsFederationParameterNames.Wres); }
            set { SetParameter(WsFederationConstants.WsFederationParameterNames.Wres, value); }
        }

        /// <summary>
        /// Gets or sets 'wresult'.
        /// </summary>
        public string Wresult
        {
            get { return GetParameter(WsFederationConstants.WsFederationParameterNames.Wresult); }
            set { SetParameter(WsFederationConstants.WsFederationParameterNames.Wresult, value); }
        }

        /// <summary>
        /// Gets or sets 'wresultptr'.
        /// </summary>
        [property: System.Diagnostics.CodeAnalysis.SuppressMessage("Microsoft.Naming", "CA1704")]        
        public string Wresultptr
        {
            get { return GetParameter(WsFederationConstants.WsFederationParameterNames.Wresultptr); }
            set { SetParameter(WsFederationConstants.WsFederationParameterNames.Wresultptr, value); }
        }

        /// <summary>
        /// Gets or sets 'wtrealm'.
        /// </summary>
        [property: System.Diagnostics.CodeAnalysis.SuppressMessage("Microsoft.Naming", "CA1704")]        
        public string Wtrealm
        {
            get { return GetParameter(WsFederationConstants.WsFederationParameterNames.Wtrealm); }
            set { SetParameter(WsFederationConstants.WsFederationParameterNames.Wtrealm, value); }
        }
    }
}
