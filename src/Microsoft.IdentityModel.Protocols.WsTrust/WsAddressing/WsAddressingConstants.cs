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

namespace Microsoft.IdentityModel.Protocols.WsAddressing
{
    /// <summary>
    /// Constants for WS-Addressing namespace and prefix.
    /// see: https://www.w3.org/Submission/ws-addressing/
    /// </summary>
    public abstract class WsAddressingConstants : WsConstantsBase
    {
        /// <summary>
        /// Gets the list of namespaces that are recognized by this runtime.
        /// </summary>
        public static IList<string> KnownNamespaces { get; } = new List<string> { "http://www.w3.org/2005/08/addressing", "http://schemas.xmlsoap.org/ws/2004/08/addressing" };

        /// <summary>
        /// Gets constants for WS-Addressing 1.0
        /// </summary>
        public static WsAddressing10Constants Addressing10 { get; } = new WsAddressing10Constants();

        /// <summary>
        /// Gets constants for WS-Addressing 200408
        /// </summary>
        public static WsAddressing200408Constants Addressing200408 { get; } = new WsAddressing200408Constants();
    }

    /// <summary>
    /// Provides constants for WS-Addressing 1.0
    /// </summary>
    public class WsAddressing10Constants : WsAddressingConstants
    {
        /// <summary>
        /// Instantiates WS-Addressing 1.0
        /// </summary>
        public WsAddressing10Constants()
        {
            Namespace = "http://www.w3.org/2005/08/addressing";
            Prefix = "wsa";
        }
    }

    /// <summary>
    /// Provides constants for WS-Addressing 200408
    /// </summary>
    public class WsAddressing200408Constants : WsAddressingConstants
    {
        /// <summary>
        /// Instantiates WS-Addressing 200408
        /// </summary>
        public WsAddressing200408Constants()
        {
            Namespace = "http://schemas.xmlsoap.org/ws/2004/08/addressing";
            Prefix = "wsa";
        }
    }
}
