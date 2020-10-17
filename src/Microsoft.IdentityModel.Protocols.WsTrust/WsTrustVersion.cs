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

namespace Microsoft.IdentityModel.Protocols.WsTrust
{
    /// <summary>
    /// Types for identifying a version of WSTrust.
    /// These are used by the <see cref="WsTrustSerializer"/> to identify the version of WSTrust to use when creating a <see cref="WsTrustMessage"/>.
    /// <para>see: http://specs.xmlsoap.org/ws/2005/02/trust/WS-Trust.pdf </para>
    /// <para>see: http://docs.oasis-open.org/ws-sx/ws-trust/200512/ws-trust-1.3-os.html </para>
    /// </summary>
    public abstract class WsTrustVersion
    {
        /// <summary>
        /// Identifies WSTrust Feb2005.
        /// </summary>
        public static WsTrustVersion TrustFeb2005 = new WsTrustFeb2005Version();

        /// <summary>
        /// Identifies WSTrust 1.3.
        /// </summary>
        public static WsTrustVersion Trust13 = new WsTrust13Version();

        /// <summary>
        /// Identifies WSTrust 1.4.
        /// </summary>
        public static WsTrustVersion Trust14 = new WsTrust14Version();
    }

    /// <summary>
    /// Type identifying WSTrust Feb2005
    /// </summary>
    internal class WsTrustFeb2005Version : WsTrustVersion {}

    /// <summary>
    /// Type identifying WSTrust 1.3
    /// </summary>
    internal class WsTrust13Version : WsTrustVersion {}

    /// <summary>
    /// Type identifying WSTrust 1.4
    /// </summary>
    internal class WsTrust14Version : WsTrustVersion {}
}
