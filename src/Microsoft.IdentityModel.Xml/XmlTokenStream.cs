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


using System;
using System.Xml;
using Microsoft.IdentityModel.Logging;

namespace Microsoft.IdentityModel.Xml
{
    public class XmlTokenStream
    {
        // TODO - remove dynamic adding.
        // Add constructor to TokenEntry that takes type / value
        private int _count;
        private XmlTokenEntry[] _entries;
        private string _excludedElement;
        private int? _excludedElementDepth;
        private string _excludedElementNamespace;

        public XmlTokenStream(int initialSize)
        {
            if (initialSize < 1)
                throw LogHelper.LogExceptionMessage(new ArgumentOutOfRangeException("initialSize ValueMustBeGreaterThanZero"));

            _entries = new XmlTokenEntry[initialSize];
        }

        // This constructor is used by the Trim method to reduce the size of the XmlTokenEntry array to the minimum required.
        public XmlTokenStream(XmlTokenStream other)
        {
            _count = other._count;
            _excludedElement = other._excludedElement;
            _excludedElementDepth = other._excludedElementDepth;
            _excludedElementNamespace = other._excludedElementNamespace;
            _entries = new XmlTokenEntry[_count];
            Array.Copy(other._entries, _entries, _count);
        }

        public void Add(XmlNodeType type, string value)
        {
            EnsureCapacityToAdd();
            _entries[_count++].Set(type, value);
        }

        public void AddAttribute(string prefix, string localName, string namespaceUri, string value)
        {
            EnsureCapacityToAdd();
            _entries[_count++].SetAttribute(prefix, localName, namespaceUri, value);
        }

        public void AddElement(string prefix, string localName, string namespaceUri, bool isEmptyElement)
        {
            EnsureCapacityToAdd();
            _entries[_count++].SetElement(prefix, localName, namespaceUri, isEmptyElement);
        }

        void EnsureCapacityToAdd()
        {
            if (_count == _entries.Length)
            {
                XmlTokenEntry[] newBuffer = new XmlTokenEntry[_entries.Length * 2];
                Array.Copy(_entries, 0, newBuffer, 0, _count);
                _entries = newBuffer;
            }
        }

        public void SetElementExclusion(string excludedElement, string excludedElementNamespace)
        {
            SetElementExclusion(excludedElement, excludedElementNamespace, null);
        }

        public void SetElementExclusion(string excludedElement, string excludedElementNamespace, int? excludedElementDepth)
        {
            _excludedElement = excludedElement;
            _excludedElementDepth = excludedElementDepth;
            _excludedElementNamespace = excludedElementNamespace;
        }

        /// <summary>
        /// Free unneeded entries from array
        /// </summary>
        /// <returns></returns>
        public XmlTokenStream Trim()
        {
            return new XmlTokenStream(this);
        }

        public XmlTokenStreamWriter GetWriter()
        {
            return new XmlTokenStreamWriter(_entries, _count, _excludedElement, _excludedElementDepth, _excludedElementNamespace);
        }

        public void WriteTo(XmlDictionaryWriter writer)
        {
            GetWriter().WriteTo(writer);
        }
    }
}
