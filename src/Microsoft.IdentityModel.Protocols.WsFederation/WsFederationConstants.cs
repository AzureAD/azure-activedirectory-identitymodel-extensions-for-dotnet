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

namespace Microsoft.IdentityModel.Protocols.WsFederation
{

    /// <summary>
    /// Constants for WsFederation actions.
    /// </summary>
    public static class WsFederationActions
    {
        #pragma warning disable 1591

        public const string Attribute = "wattr1.0";
        public const string Pseudonym = "wpseudo1.0";
        public const string SignIn = "wsignin1.0";
        public const string SignOut = "wsignout1.0";
        public const string SignOutCleanup = "wsignoutcleanup1.0";
        
        #pragma warning restore 1591
    }

    /// <summary>
    /// Constants defined for WsFederation.
    /// </summary>
    public static class WsFederationConstants
    {        
        #pragma warning disable 1591

        public const string Namespace = "http://docs.oasis-open.org/wsfed/federation/200706";

        #pragma warning restore 1591
    }

    /// <summary>
    /// Constants for WsFederation Fault codes.
    /// </summary>
    public static class WsFederationFaultCodes
    {
        #pragma warning disable 1591

        public const string AlreadySignedIn = "AlreadySignedIn";
        public const string BadRequest = "BadRequest";
        public const string IssuerNameNotSupported = "IssuerNameNotSupported";
        public const string NeedFresherCredentials = "NeedFresherCredentials";
        public const string NoMatchInScope = "NoMatchInScope";
        public const string NoPseudonymInScope = "NoPseudonymInScope";
        public const string NotSignedIn = "NotSignedIn";
        public const string RstParameterNotAccepted = "RstParameterNotAccepted";
        public const string SpecificPolicy = "SpecificPolicy";
        public const string UnsupportedClaimsDialect = "UnsupportedClaimsDialect";
        public const string UnsupportedEncoding = "UnsupportedEncoding";

        #pragma warning restore 1591
    }

    /// <summary>
    /// Defines the WsFederation Constants
    /// </summary>
    public static class WsFederationParameterNames
    {
        #pragma warning disable 1591

        public const string Wa = "wa";
        public const string Wattr = "wattr";
        public const string Wattrptr = "wattrptr";
        public const string Wauth = "wauth";
        public const string Wct = "wct";
        public const string Wctx = "wctx";
        public const string Wencoding = "wencoding";
        public const string Wfed = "wfed";
        public const string Wfresh = "wfresh";
        public const string Whr = "whr";
        public const string Wp = "wp";
        public const string Wpseudo = "wpseudo";
        public const string Wpseudoptr = "wpseudoptr";
        public const string Wreply = "wreply";
        public const string Wreq = "wreq";
        public const string Wreqptr = "wreqptr";
        public const string Wres = "wres";
        public const string Wresult = "wresult";
        public const string Wresultptr = "wresultptr";
        public const string Wtrealm = "wtrealm";
        
        #pragma warning restore 1591
    }
}
 
