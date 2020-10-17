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

namespace Microsoft.IdentityModel.Protocols.WsFed
{
    /// <summary>
    /// Constants: WS-Federation namespace and prefix.
    /// <para>see: http://docs.oasis-open.org/wsfed/federation/v1.2/os/ws-federation-1.2-spec-os.html </para>
    /// </summary>
    public abstract class WsFedConstants : WsConstantsBase
    {
        /// <summary>
        /// Gets the list of namespaces that are recognized by this runtime.
        /// </summary>
        public static IList<string> KnownNamespaces { get; } = new List<string> { "http://docs.oasis-open.org/wsfed/federation/200706" };

        /// <summary>
        /// Gets the list of auth namespaces that are recognized by this runtime.
        /// </summary>
        public static IList<string> KnownAuthNamespaces { get; } = new List<string> { "http://docs.oasis-open.org/wsfed/authorization/200706" };

        /// <summary>
        /// Gets constants for WS-Federation 1.2
        /// </summary>
        public static WsFed12Constants Fed12 { get; } = new WsFed12Constants();

        /// <summary>
        /// Gets the auth namespace for WS-Federation.
        /// </summary>
        public string AuthNamespace { get; protected set; }

        /// <summary>
        /// Gets the auth prefix for WS-Federation.
        /// </summary>
        public string AuthPrefix { get; protected set; }

        /// <summary>
        /// Gets the privacy namespace for WS-Federation.
        /// </summary>
        public string PrivacyNamespace { get; protected set; }

        /// <summary>
        /// Gets the privacy prefix for WS-Federation.
        /// </summary>
        public string PrivacyPrefix { get; protected set; }

        /// <summary>
        /// Gets the schema location for WS-Federation.
        /// </summary>
        public string SchemaLocation { get; protected set; }
    }

    /// <summary>
    /// Constants: WS-Federation 1.2 namespace and prefix.
    /// </summary>
    public class WsFed12Constants : WsFedConstants
    {
        /// <summary>
        /// Instantiates WS-Federation 1.2
        /// </summary>
        public WsFed12Constants() 
        {
            AuthNamespace = "http://docs.oasis-open.org/wsfed/authorization/200706";
            AuthPrefix = "auth";
            Prefix = "fed";
            PrivacyNamespace = "http://docs.oasis-open.org/wsfed/privacy/200706";
            PrivacyPrefix = "priv";
            Namespace = "http://docs.oasis-open.org/wsfed/federation/200706";
            SchemaLocation = "http://docs.oasis-open.org/ws-sx/ws-trust/200512/ws-trust-1.3.xsd";
        }
    }
}
