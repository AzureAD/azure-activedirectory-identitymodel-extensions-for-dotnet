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
using System.IO;
using System.Security.Cryptography;
using System.Xml;
using Microsoft.IdentityModel.Logging;
using Microsoft.IdentityModel.Tokens;

namespace Microsoft.IdentityModel.Xml
{
    class ExclusiveCanonicalizationTransform : Transform
    {
        string _inclusiveNamespacesPrefixList;
        string[] _inclusivePrefixes;
        string _inclusiveListElementPrefix = ExclusiveC14NStrings.Prefix;
        string _prefix = XmlSignatureStrings.Prefix;
        readonly bool _isCanonicalizationMethod;

        public ExclusiveCanonicalizationTransform()
            : this(false)
        {
        }

        public ExclusiveCanonicalizationTransform(bool isCanonicalizationMethod)
            : this(isCanonicalizationMethod, false)
        {
        }

        public ExclusiveCanonicalizationTransform(bool isCanonicalizationMethod, bool includeComments)
        {
            _isCanonicalizationMethod = isCanonicalizationMethod;
            IncludeComments = includeComments;
            Algorithm = includeComments ? SecurityAlgorithmStrings.ExclusiveC14nWithComments : SecurityAlgorithmStrings.ExclusiveC14n;
        }

        public bool IncludeComments
        {
            get;
            private set;
        }

        public string InclusiveNamespacesPrefixList
        {
            get
            {
                return _inclusiveNamespacesPrefixList;
            }
            set
            {
                _inclusiveNamespacesPrefixList = value;
                _inclusivePrefixes = TokenizeInclusivePrefixList(value);
            }
        }

        public override bool NeedsInclusiveContext
        {
            get { return GetInclusivePrefixes() != null; }
        }

        public string[] GetInclusivePrefixes()
        {
            return _inclusivePrefixes;
        }

        private CanonicalizationDriver GetConfiguredDriver(SignatureResourcePool resourcePool)
        {
            CanonicalizationDriver driver = resourcePool.TakeCanonicalizationDriver();
            driver.IncludeComments = IncludeComments;
            driver.SetInclusivePrefixes(_inclusivePrefixes);
            return driver;
        }

        // multi-transform case, inefficient path
        public override object Process(object input, SignatureResourcePool resourcePool)
        {
            var xmlReader = input as XmlReader;
            if (xmlReader != null)
            {
                var driver = GetConfiguredDriver(resourcePool);
                driver.SetInput(xmlReader);
                return driver.GetMemoryStream();
            }

            var securityElement = input as ISecurityElement;
            if (securityElement != null)
            {
                MemoryStream stream = new MemoryStream();
                XmlDictionaryWriter utf8Writer = resourcePool.TakeUtf8Writer();
                utf8Writer.StartCanonicalization(stream, false, null);
                securityElement.WriteTo(utf8Writer);
                utf8Writer.EndCanonicalization();
                stream.Seek(0, SeekOrigin.Begin);
                return stream;
            }

            throw LogHelper.LogExceptionMessage(new SecurityTokenException("UnsupportedInputTypeForTransform"));
        }

        // common single-transform case; fold directly into a digest
        public override byte[] ProcessAndDigest(object input, SignatureResourcePool resourcePool, string digestAlgorithm)
        {
            HashAlgorithm hash = resourcePool.TakeHashAlgorithm(digestAlgorithm);
            ProcessAndDigest(input, resourcePool, hash);
            return hash.Hash;
        }

        public void ProcessAndDigest(object input, SignatureResourcePool resourcePool, HashAlgorithm hash)
        {
            HashStream hashStream = resourcePool.TakeHashStream(hash);

            XmlReader reader = input as XmlReader;
            if (reader != null)
            {
                ProcessReaderInput(reader, resourcePool, hashStream);
            }
            else if (input is ISecurityElement)
            {
                XmlDictionaryWriter utf8Writer = resourcePool.TakeUtf8Writer();
                utf8Writer.StartCanonicalization(hashStream, IncludeComments, GetInclusivePrefixes());
                (input as ISecurityElement).WriteTo(utf8Writer);
                utf8Writer.EndCanonicalization();
            }
            else
            {
                throw LogHelper.LogExceptionMessage(new SecurityTokenException("UnsupportedInputTypeForTransform"));
            }

            hashStream.FlushHash();
        }

        void ProcessReaderInput(XmlReader reader, SignatureResourcePool resourcePool, HashStream hashStream)
        {
            reader.MoveToContent();
            XmlDictionaryReader dictionaryReader = reader as XmlDictionaryReader;
            if (dictionaryReader != null && dictionaryReader.CanCanonicalize)
            {
                dictionaryReader.StartCanonicalization(hashStream, IncludeComments, GetInclusivePrefixes());
                dictionaryReader.Skip();
                dictionaryReader.EndCanonicalization();
            }
            else
            {
                CanonicalizationDriver driver = GetConfiguredDriver(resourcePool);
                driver.SetInput(reader);
                driver.WriteTo(hashStream);
            }
        }

        public override void ReadFrom(XmlDictionaryReader reader, bool preserveComments)
        {
            string elementName = _isCanonicalizationMethod ? XmlSignatureStrings.CanonicalizationMethod : XmlSignatureStrings.Transform;
            reader.MoveToStartElement(elementName, XmlSignatureStrings.Namespace);
            _prefix = reader.Prefix;
            bool isEmptyElement = reader.IsEmptyElement;
            Algorithm = reader.GetAttribute(XmlSignatureStrings.Algorithm, null);
            if (string.IsNullOrEmpty(Algorithm))
            {
                throw LogHelper.LogExceptionMessage(new SecurityTokenException("dictionaryManager.XmlSignatureDictionary.Algorithm"));
            }

            if (Algorithm == SecurityAlgorithmStrings.ExclusiveC14nWithComments)
            {
                // to include comments in canonicalization, two conditions need to be met
                // 1. the Reference must be an xpointer.
                // 2. the transform must be #withComments
                IncludeComments = preserveComments && true;
            }
            else if (Algorithm == SecurityAlgorithmStrings.ExclusiveC14n)
            {
                IncludeComments = false;
            }
            else
            {
                throw LogHelper.LogExceptionMessage(new CryptographicException("dictionaryManager.XmlSignatureDictionary.Algorithm"));
                //throw LogHelper.LogExceptionMessage(new CryptographicException(SR.GetString(SR.ID6005, algorithm)));
            }

            reader.Read();
            reader.MoveToContent();

            if (!isEmptyElement)
            {
                if (reader.IsStartElement(ExclusiveC14NStrings.InclusiveNamespaces, ExclusiveC14NStrings.Namespace))
                {
                    reader.MoveToStartElement(ExclusiveC14NStrings.InclusiveNamespaces, ExclusiveC14NStrings.Namespace);
                    _inclusiveListElementPrefix = reader.Prefix;
                    bool emptyElement = reader.IsEmptyElement;
                    // We treat PrefixList as optional Attribute.
                    InclusiveNamespacesPrefixList = reader.GetAttribute(ExclusiveC14NStrings.PrefixList, null);
                    reader.Read();
                    if (!emptyElement)
                        reader.ReadEndElement();
                }
                reader.MoveToContent();
                reader.ReadEndElement(); // Transform
            }
        }

        public override void WriteTo(XmlDictionaryWriter writer)
        {
            var elementName = _isCanonicalizationMethod ?
                XmlSignatureStrings.CanonicalizationMethod : XmlSignatureStrings.Transform;
            writer.WriteStartElement(_prefix, elementName, XmlSignatureStrings.Namespace);
            writer.WriteAttributeString(XmlSignatureStrings.Algorithm, null, Algorithm);

            if (InclusiveNamespacesPrefixList != null)
            {
                writer.WriteStartElement(_inclusiveListElementPrefix, ExclusiveC14NStrings.InclusiveNamespaces, ExclusiveC14NStrings.Namespace);
                writer.WriteAttributeString(ExclusiveC14NStrings.PrefixList, null, InclusiveNamespacesPrefixList);
                writer.WriteEndElement(); // InclusiveNamespaces
            }

            writer.WriteEndElement(); // Transform
        }

        static string[] TokenizeInclusivePrefixList(string prefixList)
        {
            if (prefixList == null)
            {
                return null;
            }
            string[] prefixes = prefixList.Split(null);
            int count = 0;
            for (int i = 0; i < prefixes.Length; i++)
            {
                string prefix = prefixes[i];
                if (prefix == "#default")
                {
                    prefixes[count++] = string.Empty;
                }
                else if (prefix.Length > 0)
                {
                    prefixes[count++] = prefix;
                }
            }
            if (count == 0)
            {
                return null;
            }
            else if (count == prefixes.Length)
            {
                return prefixes;
            }
            else
            {
                string[] result = new string[count];
                Array.Copy(prefixes, result, count);
                return result;
            }
        }
    }
}
