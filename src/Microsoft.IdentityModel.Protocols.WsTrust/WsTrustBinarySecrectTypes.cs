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
    /// Abstract class for singleton pattern for multipule WsTrust versions for BinarySecretTypes.
    /// </summary>
    /// <typeparam name="T"></typeparam>
    public abstract class WsTrustBinarySecretTypes<T> : WsTrustBinarySecretTypes where T : new()
    {
        private static T _instance;

        /// <summary>
        /// Implements singleton pattern.
        /// </summary>
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
    /// Values for BinarySecrectTypes for WsTrust Feb2005, 1.3 and 1.4.
    /// </summary>
    public abstract class WsTrustBinarySecretTypes
    {
        /// <summary>
        /// Gets the an instance of WsTrust Feb2005 BinarySecretTypes.
        /// <para>see: http://specs.xmlsoap.org/ws/2005/02/trust/WS-Trust.pdf </para>
        /// </summary>
        public static WsTrustFeb2005BinarySecretTypes TrustFeb2005 => WsTrustFeb2005BinarySecretTypes.Instance;

        /// <summary>
        /// Gets the an instance of WsTrust 1.3 BinarySecretTypes.
        /// <para>see: http://specs.xmlsoap.org/ws/2005/02/trust/WS-Trust.pdf </para>
        /// </summary>
        public static WsTrust13BinarySecretTypes Trust13 => WsTrust13BinarySecretTypes.Instance;

        /// <summary>
        /// Gets the an instance of WsTrust 1.4 BinarySecretTypes.
        /// <para>see: http://specs.xmlsoap.org/ws/2005/02/trust/WS-Trust.pdf </para>
        /// </summary>
        public static WsTrust14BinarySecretTypes Trust14 => WsTrust14BinarySecretTypes.Instance;

        /// <summary>
        /// Gets the AsymmetricKey value.
        /// </summary>
        public string AsymmetricKey { get; protected set; }

        /// <summary>
        /// Gets the Nonce value.
        /// </summary>
        public string Nonce { get; protected set; }

        /// <summary>
        /// Gets the Symmetric value.
        /// </summary>
        public string SymmetricKey { get; protected set; }
    }

    /// <summary>
    /// Values for BinarySecretTypes for WsTrust Feb2005.
    /// </summary>
    public class WsTrustFeb2005BinarySecretTypes : WsTrustBinarySecretTypes<WsTrustFeb2005BinarySecretTypes>
    {
        /// <summary>
        /// Creates an instance of <see cref="WsTrustFeb2005BinarySecretTypes"/>.
        /// <para>The property <see cref="WsTrustBinarySecretTypes.TrustFeb2005"/>  maintains a singleton instance of BinarySecretTypes for WsTrust Feb2005.</para>
        /// </summary>
        public WsTrustFeb2005BinarySecretTypes()
        {
            AsymmetricKey = "http://schemas.xmlsoap.org/ws/2005/02/trust/AsymmetricKey";
            Nonce = "http://schemas.xmlsoap.org/ws/2005/02/trust/Nonce";
            SymmetricKey = "http://schemas.xmlsoap.org/ws/2005/02/trust/SymmetricKey";
        }
    }

    /// <summary>
    /// Values for BinarySecretTypes for WsTrust 1.3.
    /// </summary>
    public class WsTrust13BinarySecretTypes : WsTrustBinarySecretTypes<WsTrust13BinarySecretTypes>
    {
        /// <summary>
        /// Creates an instance of <see cref="WsTrust13BinarySecretTypes"/>.
        /// <para>The property <see cref="WsTrustBinarySecretTypes.TrustFeb2005"/>  maintains a singleton instance of BinarySecretTypes for WsTrust 1.3.</para>
        /// </summary>
        public WsTrust13BinarySecretTypes()
        {
            AsymmetricKey = "http://docs.oasis-open.org/ws-sx/ws-trust/200512/AsymmetricKey";
            Nonce = "http://docs.oasis-open.org/ws-sx/ws-trust/200512/Nonce";
            SymmetricKey = "http://docs.oasis-open.org/ws-sx/ws-trust/200512/SymmetricKey"; ;
        }
    }

    /// <summary>
    /// Values for BinarySecretTypes for WsTrust 1.4.
    /// </summary>
    public class WsTrust14BinarySecretTypes : WsTrustBinarySecretTypes<WsTrust14BinarySecretTypes>
    {
        /// <summary>
        /// Creates an instance of <see cref="WsTrust14BinarySecretTypes"/>.
        /// <para>The property <see cref="WsTrustBinarySecretTypes.Trust14"/>  maintains a singleton instance of BinarySecretTypes for WsTrust 1.4.</para>
        /// </summary>
        public WsTrust14BinarySecretTypes()
        {
            AsymmetricKey = "http://docs.oasis-open.org/ws-sx/ws-trust/200512/Bearer";
            Nonce = "http://docs.oasis-open.org/ws-sx/ws-trust/200512/Nonce";
            SymmetricKey = "http://docs.oasis-open.org/ws-sx/ws-trust/200512/SymmetricKey";
        }
    }
}
