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

using System.Xml;

namespace Microsoft.IdentityModel.Xml
{
    public struct XmlTokenEntry
    {
        internal XmlNodeType _nodeType;
        internal string _prefix;
        internal string _localName;
        internal string _namespaceUri;
        private string _value;

        public bool IsEmptyElement
        {
            get { return _value == null; }
            set { _value = value ? null : ""; }
        }

        public string Value
        {
            get { return _value; }
        }

        public void Set(XmlNodeType nodeType, string value)
        {
            _nodeType = nodeType;
            _value = value;
        }

        public void SetAttribute(string prefix, string localName, string namespaceUri, string value)
        {
            _nodeType = XmlNodeType.Attribute;
            _prefix = prefix;
            _localName = localName;
            _namespaceUri = namespaceUri;
            _value = value;
        }

        public void SetElement(string prefix, string localName, string namespaceUri, bool isEmptyElement)
        {
            _nodeType = XmlNodeType.Element;
            _prefix = prefix;
            _localName = localName;
            _namespaceUri = namespaceUri;
            IsEmptyElement = isEmptyElement;
        }
    }
}
