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
    /// Constants KeyTypes for WsTrust Feb2005, 1.3 and 1.4.
    /// <para>see: http://docs.oasis-open.org/ws-sx/ws-trust/200512/ws-trust-1.3-os.html </para>
    /// </summary>
    public abstract class WsTrustKeyTypes
    {
        /// <summary>
        /// Gets KeyTypes constants for WSTrust Feb2005
        /// </summary>
        public static WsTrustFeb2005KeyTypes TrustFeb2005 { get; } = new WsTrustFeb2005KeyTypes();

        /// <summary>
        /// Gets KeyTypes constants for WSTrust 1.3
        /// </summary>
        public static WsTrust13KeyTypes Trust13 { get; } = new WsTrust13KeyTypes();

        /// <summary>
        /// Gets KeyTypes constants for WSTrust 1.4
        /// </summary>
        public static WsTrust14KeyTypes Trust14 { get; } = new WsTrust14KeyTypes();

        /// <summary>
        /// Gets Bearer constant type for WSTrust.
        /// </summary>
        public string Bearer { get; protected set; }

        /// <summary>
        /// Gets PublicKey constant type for WSTrust.
        /// </summary>
        public string PublicKey { get; protected set; }

        /// <summary>
        /// Gets PSHA1 constant type for WSTrust.
        /// </summary>
        public string PSHA1 { get; protected set; }

        /// <summary>
        /// Gets Symmetric constant type for WSTrust.
        /// </summary>
        public string Symmetric { get; protected set; }
    }

    /// <summary>
    /// Provides KeyTypes constants for WSTrust Feb2005
    /// </summary>
    public class WsTrustFeb2005KeyTypes : WsTrustKeyTypes
    {
        /// <summary>
        /// Instantiates KeyTypes for WSTrust Feb2005
        /// </summary>
        public WsTrustFeb2005KeyTypes()
        {
            Bearer = "http://schemas.xmlsoap.org/ws/2005/02/trust/Bearer";
            PSHA1 = "http://schemas.xmlsoap.org/ws/2005/02/trust/CK/PSHA1";
            PublicKey = "http://schemas.xmlsoap.org/ws/2005/02/trust/PublicKey";
            Symmetric = "http://schemas.xmlsoap.org/ws/2005/02/trust/SymmetricKey";
        }
    }

    /// <summary>
    /// Provides KeyTypes constants for WSTrust 1.3
    /// </summary>
    public class WsTrust13KeyTypes : WsTrustKeyTypes
    {
        /// <summary>
        /// Instantiates KeyTypes for WSTrust 1.3
        /// </summary>
        public WsTrust13KeyTypes()
        {
            Bearer = "http://docs.oasis-open.org/ws-sx/ws-trust/200512/Bearer";
            PSHA1 = "http://docs.oasis-open.org/ws-sx/ws-trust/200512/CK/PSHA1";
            PublicKey = "http://docs.oasis-open.org/ws-sx/ws-trust/200512/PublicKey";
            Symmetric = "http://docs.oasis-open.org/ws-sx/ws-trust/200512/SymmetricKey"; ;
        }
    }

    /// <summary>
    /// Provides KeyTypes constants for WSTrust 1.44
    /// </summary>
    public class WsTrust14KeyTypes : WsTrustKeyTypes
    {
        /// <summary>
        /// Instantiates KeyTypes for WSTrust 1.4
        /// </summary>
        public WsTrust14KeyTypes()
        {
            Bearer = "http://docs.oasis-open.org/ws-sx/ws-trust/200512/Bearer";
            PSHA1 = "http://docs.oasis-open.org/ws-sx/ws-trust/200512/CK/PSHA1";
            PublicKey = "http://docs.oasis-open.org/ws-sx/ws-trust/200512/PublicKey";
            Symmetric = "http://docs.oasis-open.org/ws-sx/ws-trust/200512/SymmetricKey";
        }
    }
}
