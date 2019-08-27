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

using System.Collections.Generic;

namespace Microsoft.IdentityModel.Protocols.WsFed
{
    public abstract class WsFedConstants<T> : WsFedConstants where T : new()
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

    public abstract class WsFedConstants : WsConstantsBase
    {
        private static IList<string> _knownAuthNamespaces = null;
        private static IList<string> _knownNamespaces = null;

        public static IList<string> KnownNamespaces
        {
            get
            {
                if (_knownNamespaces == null)
                    _knownNamespaces = new List<string> { "http://docs.oasis-open.org/wsfed/federation/200706" };

                return _knownNamespaces;
            }
        }
        public static IList<string> KnownAuthNamespaces
        {
            get
            {
                if (_knownAuthNamespaces == null)
                    _knownAuthNamespaces = new List<string> { "http://docs.oasis-open.org/wsfed/authorization/200706" };

                return _knownAuthNamespaces;
            }
        }

        public static WsFed12Constants Fed12 => WsFed12Constants.Instance;

        public WsFedConstants() {}

        public string AuthNamespace { get; protected set; }

        public string AuthPrefix { get; protected set; }

        public string PrivacyNamespace { get; protected set; }

        public string PrivacyPrefix { get; protected set; }

        public string SchemaLocation { get; protected set; }
    }

    public class WsFed12Constants : WsFedConstants<WsFed12Constants>
    {
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



