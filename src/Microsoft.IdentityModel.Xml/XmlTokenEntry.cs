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
    internal class XmlTokenEntry
    {
        internal XmlNodeType NodeType;
        internal string _prefix;
        internal string _localName;
        internal string _namespace;
        private string _value;

        public bool IsEmptyElement
        {
            get { return _value == null; }
            set { _value = value ? null : ""; }
        }

        public string Value
        {
            get; private set;
        }

        public XmlTokenEntry(XmlNodeType nodeType, string value)
        {
            NodeType = nodeType;
            Value = value;
        }

        public XmlTokenEntry(XmlNodeType nodeType, string prefix, string localName, string @namespace, string value)
        {
            NodeType = nodeType;
            _prefix = prefix;
            _localName = localName;
            _namespace = @namespace;
            Value = value;
        }

        public XmlTokenEntry(XmlNodeType nodeType, string prefix, string localName, string @namespace, bool isEmptyElement)
        {
            NodeType = nodeType;
            _prefix = prefix;
            _localName = localName;
            _namespace = @namespace;
            IsEmptyElement = isEmptyElement;
        }
    }
}
