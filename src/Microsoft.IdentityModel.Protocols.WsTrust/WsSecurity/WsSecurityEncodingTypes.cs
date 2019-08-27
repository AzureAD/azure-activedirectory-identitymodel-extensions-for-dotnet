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

#pragma warning disable 1591

namespace Microsoft.IdentityModel.Protocols.WsSecurity
{
    public abstract class WsSecurityEncodingTypes<T> : WsSecurityEncodingTypes where T : new()
    {
        private static T _instance;

        public static T Instance
        {
            get
            {
                if (_instance == null)
                    _instance = new T();

                return _instance;
            }
        }
    }

    /// <summary>
    /// Provides encodingtypes for WS-Security 1.0 and 1.1.
    /// </summary>
    public abstract class WsSecurityEncodingTypes
    {
        public static WsSecurity10EncodingTypes WsSecurity10 => WsSecurity10EncodingTypes.Instance;

        public static WsSecurity11EncodingTypes WsSecurity11 => WsSecurity11EncodingTypes.Instance;

        public WsSecurityEncodingTypes() {}

        public string Base64 { get; protected set; }

        public string HexBinary { get; protected set; }

        public string Text { get; protected set; }
    }

    /// Provides encodingtypes for WS-Security 1.0.
    public class WsSecurity10EncodingTypes : WsSecurityEncodingTypes<WsSecurity10EncodingTypes>
    {
        public WsSecurity10EncodingTypes()
        {
            Base64 = "http://docs.oasis-open.org/wss/2004/01/oasis-200401-wss-soap-message-security-1.0/#Base64Binary";
            HexBinary = "http://docs.oasis-open.org/wss/2004/01/oasis-200401-wss-soap-message-security-1.0/#HexBinary";
            Text = "http://docs.oasis-open.org/wss/2004/01/oasis-200401-wss-soap-message-security-1.0/#Text";
        }
    }

    /// Provides encodingtypes for WS-Security 1.1.
    public class WsSecurity11EncodingTypes : WsSecurityEncodingTypes<WsSecurity11EncodingTypes>
    {
        public WsSecurity11EncodingTypes()
        {
            Base64 = "http://docs.oasis-open.org/wss/oasis-wss-soap-message-security-1.1/#Base64Binary";
            HexBinary = "http://docs.oasis-open.org/wss/oasis-wss-soap-message-security-1.1/#HexBinary";
            Text = "http://docs.oasis-open.org/wss/oasis-wss-soap-message-security-1.1/#Text";
        }
    }
}
