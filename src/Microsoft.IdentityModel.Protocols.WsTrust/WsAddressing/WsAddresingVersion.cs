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

using Microsoft.IdentityModel.Protocols.WsTrust;

namespace Microsoft.IdentityModel.Protocols.WsAddressing
{
    /// <summary>
    /// Types for identifying a version of WS-Addressing.
    /// These are passed to the <see cref="WsTrustSerializer"/> to identify the version of WsTrust to use when creating a <see cref="WsTrustMessage"/>.
    /// <para>see: http://specs.xmlsoap.org/ws/2005/02/trust/WS-Trust.pdf </para>
    /// <para>see: http://docs.oasis-open.org/ws-sx/ws-trust/200512/ws-trust-1.3-os.html </para>
    /// </summary>
    public abstract class WsAddressingVersion
    {
        /// <summary>
        /// Identifies WS-Addressing 1.0.
        /// </summary>
        public static WsAddressingVersion Addressing10 = new WsAddressing10Version();

        /// <summary>
        /// Identifies WS-Addressing 200408
        /// </summary>
        public static WsAddressingVersion Addressing200408 = new WsAddressing200408Version();
    }

    /// <summary>
    /// Type identifying  WS-Addressing 1.0.
    /// </summary>
    public class WsAddressing10Version : WsAddressingVersion { }

    /// <summary>
    /// Type identifying WS-Addressing 200408.
    /// </summary>
    public class WsAddressing200408Version : WsAddressingVersion { }
}
