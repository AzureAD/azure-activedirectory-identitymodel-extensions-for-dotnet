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
    /// Constants: WS-Trust FaultCodes.
    /// <para>see: http://docs.oasis-open.org/ws-sx/ws-trust/200512/ws-trust-1.3-os.html </para>
    /// </summary>
    public static class WsTrustFaultCodes
    {
        /// <summary>
        /// Gets the value for "FailedAuthentication"
        /// </summary>
        public const string FailedAuthentication = "FailedAuthentication";

        /// <summary>
        /// Gets the value for "FailedCheck"
        /// </summary>
        public const string FailedCheck = "FailedCheck";

        /// <summary>
        /// Gets the value for "InvalidSecurity"
        /// </summary>
        public const string InvalidSecurity = "InvalidSecurity";

        /// <summary>
        /// Gets the value for "InvalidSecurityToken"
        /// </summary>
        public const string InvalidSecurityToken = "InvalidSecurityToken";

        /// <summary>
        /// Gets the value for "MessageExpired"
        /// </summary>
        public const string MessageExpired = "MessageExpired";

        /// <summary>
        /// Gets the value for "SecurityTokenUnavailable"
        /// </summary>
        public const string SecurityTokenUnavailable = "SecurityTokenUnavailable";

        /// <summary>
        /// Gets the value for "UnsupportedAlgorithm"
        /// </summary>
        public const string UnsupportedAlgorithm = "UnsupportedAlgorithm";

        /// <summary>
        /// Gets the value for "UnsupportedSecurityToken"
        /// </summary>
        public const string UnsupportedSecurityToken = "UnsupportedSecurityToken";
    }
}
