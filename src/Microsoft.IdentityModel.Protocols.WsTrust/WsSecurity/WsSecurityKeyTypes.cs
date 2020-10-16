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

namespace Microsoft.IdentityModel.Protocols.WsSecurity
{
    /// <summary>
    /// Constants for key types for WS-Security 1.0 and 1.1.
    /// <para>see: https://www.oasis-open.org/committees/download.php/16790/wss-v1.1-spec-os-SOAPMessageSecurity.pdf </para>
    /// </summary>
    public abstract class WsSecurityKeyTypes
    {
        /// <summary>
        /// Gets key type constants for WS-Security 1.0
        /// </summary>
        public static WsSecurity10KeyTypes WsSecurity10 { get; } = new WsSecurity10KeyTypes();

        /// <summary>
        /// Gets key type constants for WS-Security 1.1
        /// </summary>
        public static WsSecurity11KeyTypes WsSecurity11 { get; } = new WsSecurity11KeyTypes();

        /// <summary>
        /// Gets Sha1Thumbprint constant type for WS-Security
        /// </summary>
        public string Sha1Thumbprint { get; protected set; }
    }

    /// <summary>
    /// Provides key type constants for WS-Security 1.0.
    /// </summary>
    public class WsSecurity10KeyTypes : WsSecurityKeyTypes
    {
        /// <summary>
        /// Instantiates key types for WS-Security 1.0
        /// </summary>
        public WsSecurity10KeyTypes()
        {
            Sha1Thumbprint = "http://docs.oasis-open.org/wss/2004/01/oasis-200401-wss-soap-message-security-1.0/#ThumbprintSHA1";
        }
    }

    /// <summary>
    /// Provides key type constants for WS-Security 1.1.
    /// </summary>
    public class WsSecurity11KeyTypes : WsSecurityKeyTypes
    {
        /// <summary>
        /// Instantiates key types for WS-Security 1.1
        /// </summary>
        public WsSecurity11KeyTypes()
        {
            Sha1Thumbprint = "http://docs.oasis-open.org/wss/oasis-wss-soap-message-security-1.1/#ThumbprintSHA1";
        }
    }
}
