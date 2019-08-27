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

namespace Microsoft.IdentityModel.Protocols.WsTrust
{
    public abstract class WsTrustConstants<T> : WsTrustConstants where T : new()
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

    /// <summary>
    /// Provides constants for WS-Trust Feb2005, 1.3 and 1.4.
    /// </summary>
    public abstract class WsTrustConstants : WsConstantsBase
    {
        private static IList<string> _knownNamespaces = null;

        public WsTrustActions WsTrustActions { get; protected set; }

        public WsTrustKeyTypes WsTrustKeyTypes { get; protected set; }

        public static IList<string> KnownNamespaces
        {
            get
            {
                if (_knownNamespaces == null)
                    _knownNamespaces = new List<string> { "http://schemas.xmlsoap.org/ws/2005/02/trust", "http://docs.oasis-open.org/ws-sx/ws-trust/200512", "http://docs.oasis-open.org/ws-sx/ws-trust/200802" };

                return _knownNamespaces;
            }
        }

        public static WsTrustFeb2005Constants TrustFeb2005 => WsTrustFeb2005Constants.Instance;

        public static WsTrust13Constants Trust13 => WsTrust13Constants.Instance;

        public static WsTrust14Constants Trust14 => WsTrust14Constants.Instance;
    }

    /// <summary>
    /// Provides constants for WS-Trust Feb2005.
    /// </summary>
    public class WsTrustFeb2005Constants : WsTrustConstants<WsTrustFeb2005Constants>
    {
        public WsTrustFeb2005Constants()
        {
            Namespace = "http://schemas.xmlsoap.org/ws/2005/02/trust";
            Prefix = "t";
            WsTrustActions = WsTrustActions.TrustFeb2005;
            WsTrustKeyTypes = WsTrustKeyTypes.TrustFeb2005;
        }
    }

    /// <summary>
    /// Provides constants for WS-Trust 1.3.
    /// </summary>
    public class WsTrust13Constants : WsTrustConstants<WsTrust13Constants>
    {
        public WsTrust13Constants()
        {
            Namespace = "http://docs.oasis-open.org/ws-sx/ws-trust/200512";
            Prefix = "trust";
            WsTrustActions = WsTrustActions.Trust13;
            WsTrustKeyTypes = WsTrustKeyTypes.Trust13;
        }
    }

    /// <summary>
    /// Provides constants for WS-Trust 1.4.
    /// </summary>
    public class WsTrust14Constants : WsTrustConstants<WsTrust14Constants>
    {
        public WsTrust14Constants()
        {
            Namespace = "http://docs.oasis-open.org/ws-sx/ws-trust/200802";
            Prefix = "tr";
            WsTrustActions = WsTrustActions.Trust14;
            WsTrustKeyTypes = WsTrustKeyTypes.Trust14;
        }
    }
}

