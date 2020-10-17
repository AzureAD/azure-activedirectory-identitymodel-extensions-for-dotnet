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

using System.Collections.Generic;

namespace Microsoft.IdentityModel.Protocols.WsPolicy
{
    /// <summary>
    /// Constants: WS-Policy constants namespace and prefix.
    /// <para>see: http://specs.xmlsoap.org/ws/2004/09/policy/ws-policy.pdf </para>
    /// </summary>
    public abstract class WsPolicyConstants : WsConstantsBase
    {
        /// <summary>
        /// Gets the list of namespaces that are recognized by this runtime.
        /// </summary>
        public static IList<string> KnownNamespaces { get; } = new List<string> { "http://schemas.xmlsoap.org/ws/2004/09/policy", "http://www.w3.org/ns/ws-policy" };

        /// <summary>
        /// Gets constants for WS-Policy 1.2
        /// </summary>
        public static WsPolicy12Constants Policy12 { get; } = new WsPolicy12Constants();

        /// <summary>
        /// Gets constants for WS-Policy 1.5
        /// </summary>
        public static WsPolicy15Constants Policy15 { get; } = new WsPolicy15Constants();
    }

    /// <summary>
    /// Constants: WS-Policy 1.2 namespace and prefix.
    /// </summary>
    public class WsPolicy12Constants : WsPolicyConstants
    {
        /// <summary>
        /// Instantiates WS-Policy 1.2
        /// </summary>
        public WsPolicy12Constants()
        {
            Namespace = "http://schemas.xmlsoap.org/ws/2004/09/policy";
            Prefix = "wsp";
        }
    }

    /// <summary>
    /// Constants: WS-Policy 1.5 namespace and prefix.
    /// </summary>
    public class WsPolicy15Constants : WsPolicyConstants
    {
        /// <summary>
        /// Instantiates WS-Policy 1.5
        /// </summary>
        public WsPolicy15Constants()
        {
            Namespace = "http://www.w3.org/ns/ws-policy";
            Prefix = "wsp";
        }
    }
}
