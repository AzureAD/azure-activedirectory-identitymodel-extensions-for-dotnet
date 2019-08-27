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

namespace Microsoft.IdentityModel.Protocols.WsFed
{
    public abstract class WsFedAuthTypes<T> : WsFedAuthTypes where T : new()
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

    public class WsFedAuthTypes
    {
        public static WsFed12AuthTypes Fed12 => WsFed12AuthTypes.Instance;

        public WsFedAuthTypes() {}

        public string Default { get; protected set; }

        public string SmartCard { get; protected set; }

        public string Ssl { get; protected set; }

        public string SslAndKey { get; protected set; }

        public string SslAndStrongPassword { get; protected set; }

        public string SslAndStrongPasswordWithExpiration { get; protected set; }

        public string Unknown { get; protected set; }
    }

    public class WsFed12AuthTypes : WsFedAuthTypes<WsFed12AuthTypes>
    {
        public WsFed12AuthTypes()
        {
            Default = "http://schemas.xmlsoap.org/ws/2006/12/authorization/authntypes/default";
            SmartCard = "http://schemas.xmlsoap.org/ws/2006/12/authorization/authntypes/smartcard";
            Ssl = "http://schemas.xmlsoap.org/ws/2006/12/authorization/authntypes/Ssl";
            SslAndKey = "http://schemas.xmlsoap.org/ws/2006/12/authorization/authntypes/SslAndKey";
            SslAndStrongPassword = "http://schemas.xmlsoap.org/ws/2006/12/authorization/authntypes/SslAndStrongPassword";
            SslAndStrongPasswordWithExpiration = "http://schemas.xmlsoap.org/ws/2006/12/authorization/authntypes/SslAndStrongPasswordWithExpiration";
            Unknown = "http://schemas.xmlsoap.org/ws/2006/12/authorization/authntypes/unknown";
        }
    }
}


