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

namespace Microsoft.IdentityModel.Protocols
{
    public abstract class XmlEncryptionConstants<T> : XmlEncryptionConstants where T : new()
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

    public abstract class XmlEncryptionConstants : WsConstantsBase
    {
        public static XmlEncryption11Constants XmlEnc11 => XmlEncryption11Constants.Instance;

        public XmlEncryptionConstants() {}
    }

    public class XmlEncryption11Constants : XmlEncryptionConstants<XmlEncryption11Constants>
    {
        public XmlEncryption11Constants()
        {
            Namespace = "http://www.w3.org/2001/04/xmlenc#";
            Prefix = "xenc";
        }
    }
}
