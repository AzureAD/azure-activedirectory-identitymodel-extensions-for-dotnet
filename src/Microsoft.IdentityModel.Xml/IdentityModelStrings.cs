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

namespace Microsoft.IdentityModel.Xml
{
    /// <summary>
    /// Strings used in reading and writing XML tokens, metada, etc
    /// </summary>

    public static class UtilityStrings
    {
        public const string Id = "Id";
        public const string Namespace = "http://docs.oasis-open.org/wss/2004/01/oasis-200401-wss-wssecurity-utility-1.0.xsd";
        public const string Timestamp = "Timestamp";
        public const string CreatedElement = "Created";
        public const string ExpiresElement = "Expires";
        public const string Prefix = "u";
    }


    public static class WSWSSecurity10Strings
    {
        public const string FragmentBaseAddress = "http://docs.oasis-open.org/wss/2004/01/oasis-200401-wss-soap-message-security-1.0";
        public const string Namespace = "http://docs.oasis-open.org/wss/2004/01/oasis-200401-wss-wssecurity-secext-1.0.xsd";
        public const string Prefix = "wsse";
        public const string Base64EncodingType = "http://docs.oasis-open.org/wss/2004/01/oasis-200401-wss-soap-message-security-1.0#Base64Binary";
        public const string HexBinaryEncodingType = "http://docs.oasis-open.org/wss/2004/01/oasis-200401-wss-soap-message-security-1.0#HexBinary";
        public const string KerberosTokenType1510 = "http://docs.oasis-open.org/wss/oasis-wss-kerberos-token-profile-1.1#GSS_Kerberosv5_AP_REQ1510";
        public const string KerberosTokenTypeGSS = "http://docs.oasis-open.org/wss/oasis-wss-kerberos-token-profile-1.1#GSS_Kerberosv5_AP_REQ";
        public const string TextEncodingType = "http://docs.oasis-open.org/wss/2004/01/oasis-200401-wss-soap-message-security-1.0#Text";
        public const string X509TokenType = "http://docs.oasis-open.org/wss/2004/01/oasis-200401-wss-x509-token-profile-1.0#X509v3";
        public const string UPTokenPasswordTextValue = "http://docs.oasis-open.org/wss/2004/01/oasis-200401-wss-username-token-profile-1.0#PasswordText";
        public const string ValueType = "ValueType";
        public const string EncodingType = "EncodingType";
        public const string URI = "URI";
        public const string Type = "Type";
        public const string BinarySecurityToken = "BinarySecurityToken";
        public const string Reference = "Reference";
        public const string KeyIdentifier = "KeyIdentifier";
        public const string SecurityTokenReference = "SecurityTokenReference";
        public const string UsernameToken = "UsernameToken";
        public const string Username = "Username";
        public const string Password = "Password";
        public const string Nonce = "Nonce";
        public const string Created = "Created";
        public const string Base64 = FragmentBaseAddress + "#Base64Binary";
        public const string HexBinary = FragmentBaseAddress + "#HexBinary";
        public const string Text = FragmentBaseAddress + "#Text";
    }

    public static class WSWSSecurity11Strings
    {
        public const string SecurityTokenReference = "SecurityTokenReference";
        public const string TokenType = "TokenType";
        public const string FragmentBaseAddress = "http://docs.oasis-open.org/wss/oasis-wss-soap-message-security-1.1";
        public const string Namespace = "http://docs.oasis-open.org/wss/oasis-wss-wssecurity-secext-1.1.xsd";
        public const string Prefix = "wsse11";

    }
}
