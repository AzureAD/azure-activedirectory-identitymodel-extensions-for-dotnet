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
    /// Constants for BinarySecrectTypes for WsTrust Feb2005, 1.3 and 1.4.
    /// <para>see: http://docs.oasis-open.org/ws-sx/ws-trust/200512/ws-trust-1.3-os.html </para>
    /// </summary>
    public abstract class WsTrustBinarySecretTypes
    {
        /// <summary>
        /// Gets BinarySecretTypes constants for WsTrust Feb2005.
        /// </summary>
        public static WsTrustFeb2005BinarySecretTypes TrustFeb2005 { get; } = new WsTrustFeb2005BinarySecretTypes();

        /// <summary>
        /// Gets BinarySecretTypes constants for WsTrust 1.3.
        /// </summary>
        public static WsTrust13BinarySecretTypes Trust13 { get; } = new WsTrust13BinarySecretTypes();

        /// <summary>
        /// Gets BinarySecretTypes constants for WsTrust 1.4.
        /// </summary>
        public static WsTrust14BinarySecretTypes Trust14 { get; } = new WsTrust14BinarySecretTypes();

        /// <summary>
        /// Gets AsymmetricKey constant type for WSTrust
        /// </summary>
        public string AsymmetricKey { get; protected set; }

        /// <summary>
        /// Gets Nonce constant type for WSTrust
        /// </summary>
        public string Nonce { get; protected set; }

        /// <summary>
        /// Gets SymmetricKey constant type for WSTrust
        /// </summary>
        public string SymmetricKey { get; protected set; }
    }

    /// <summary>
    /// Provides BinarySecretTypes constants for WsTrust Feb2005.
    /// </summary>
    public class WsTrustFeb2005BinarySecretTypes : WsTrustBinarySecretTypes
    {
        /// <summary>
        /// Instantiates BinarySecretTypes for WsTrust Feb2005.
        /// </summary>
        public WsTrustFeb2005BinarySecretTypes()
        {
            AsymmetricKey = "http://schemas.xmlsoap.org/ws/2005/02/trust/AsymmetricKey";
            Nonce = "http://schemas.xmlsoap.org/ws/2005/02/trust/Nonce";
            SymmetricKey = "http://schemas.xmlsoap.org/ws/2005/02/trust/SymmetricKey";
        }
    }

    /// <summary>
    /// Provides BinarySecretTypes constants for WsTrust 1.3.
    /// </summary>
    public class WsTrust13BinarySecretTypes : WsTrustBinarySecretTypes
    {
        /// <summary>
        /// Instantiates BinarySecretTypes for WsTrust 1.3.
        /// </summary>
        public WsTrust13BinarySecretTypes()
        {
            AsymmetricKey = "http://docs.oasis-open.org/ws-sx/ws-trust/200512/AsymmetricKey";
            Nonce = "http://docs.oasis-open.org/ws-sx/ws-trust/200512/Nonce";
            SymmetricKey = "http://docs.oasis-open.org/ws-sx/ws-trust/200512/SymmetricKey"; ;
        }
    }

    /// <summary>
    /// Provides BinarySecretTypes constants for WsTrust 1.4.
    /// </summary>
    public class WsTrust14BinarySecretTypes : WsTrustBinarySecretTypes
    {
        /// <summary>
        /// Instantiates BinarySecretTypes for WsTrust 1.4.
        /// </summary>
        public WsTrust14BinarySecretTypes()
        {
            AsymmetricKey = "http://docs.oasis-open.org/ws-sx/ws-trust/200512/Bearer";
            Nonce = "http://docs.oasis-open.org/ws-sx/ws-trust/200512/Nonce";
            SymmetricKey = "http://docs.oasis-open.org/ws-sx/ws-trust/200512/SymmetricKey";
        }
    }
}
