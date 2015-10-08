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

namespace System.IdentityModel.Tokens.Saml
{
    /// <summary>
    /// Log messages and codes
    /// </summary>
    internal static class LogMessages
    {
#pragma warning disable 1591
        // general
        internal const string IDX10000 = "IDX10000: The parameter '{0}' cannot be a 'null' or an empty object.";
        internal const string IDX10001 = "IDX10001: The property value '{0}' cannot be a 'null' or an empty object.";
        internal const string IDX10002 = "IDX10002: The parameter '{0}' cannot be 'null' or a string containing only whitespace.";

        // properties, configuration 
        internal const string IDX10101 = "IDX10101: MaximumTokenSizeInBytes must be greater than zero. value: '{0}'";

        // token validation
        internal const string IDX10209 = "IDX10209: token has length: '{0}' which is larger than the MaximumTokenSizeInBytes: '{1}'.";
        internal const string IDX10213 = "IDX10213: SecurityTokens must be signed. SecurityToken: '{0}'.";
        internal const string IDX10221 = "IDX10221: Unable to create claims from securityToken, 'issuer' is null or empty.";
        internal const string IDX10230 = "IDX10230: Lifetime validation failed. Delegate returned false, securitytoken: '{0}'.";
        internal const string IDX10231 = "IDX10231: Audience validation failed. Delegate returned false, securitytoken: '{0}'.";

        // SecurityTokenHandler messages
        internal const string IDX10400 = "IDX10400: The '{0}', can only process SecurityTokens of type: '{1}'. The SecurityToken received is of type: '{2}'.";

        // NotSupported Exceptions
        internal const string IDX11002 = "IDX11002: This method is not supported to read a 'saml2token' use the method: ReadToken(XmlReader reader, TokenValidationParameters validationParameters).";
        internal const string IDX11003 = "IDX11003: This method is not supported to read a 'samltoken' use the method: ReadToken(XmlReader reader, TokenValidationParameters validationParameters).";
        internal const string IDX11006 = "IDX11006: This method is not supported to read a 'saml2token' use the method: ReadToken(string securityToken, TokenValidationParameters validationParameters).";
        internal const string IDX11007 = "IDX11007: This method is not supported to read a 'samltoken' use the method: ReadToken(string securityToken, TokenValidationParameters validationParameters).";

#pragma warning restore 1591


    }
}