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

namespace Microsoft.IdentityModel.Protocols.WsAddressing
{
    /// <summary>
    /// Classes for specifying WS-Addressing, 1.0 and 200408.
    /// </summary>
    public abstract class WsAddressingVersion
    {
        public static WsAddressingVersion Addressing10 = new WsAddressing10Version();

        public static WsAddressingVersion Addressing200408 = new WsAddressing200408Version();
    }

    /// <summary>
    /// Class for specifying WS-Addressing 10.
    /// </summary>
    internal class WsAddressing10Version : WsAddressingVersion { }

    /// <summary>
    /// Class for specifying WS-Addressing 200408.
    /// </summary>
    internal class WsAddressing200408Version : WsAddressingVersion { }

}
