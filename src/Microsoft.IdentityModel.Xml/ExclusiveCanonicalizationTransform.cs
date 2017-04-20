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

namespace Microsoft.IdentityModel.Xml
{
    /// <summary>
    /// Canonicalization algorithms are found in &lt;SignedInfo> and &lt;Transform>.
    /// The elment name can be: CanonicalizationMethod or Transform the actions are the same.
    /// </summary>
    public class ExclusiveCanonicalizationTransform : Transform
    {
        private string _elementName;
        private string _inclusiveListElementPrefix = ExclusiveC14NConstants.Prefix;
        private string _inclusiveNamespacesPrefixList;
        private string[] _inclusivePrefixes;
        private string _prefix = XmlSignatureConstants.Prefix;

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
            _elementName = isCanonicalizationMethod ? XmlSignatureConstants.Elements.CanonicalizationMethod : XmlSignatureConstants.Elements.Transform;
            IncludeComments = includeComments;
            Algorithm = includeComments ? XmlSignatureConstants.ExclusiveC14nWithComments : XmlSignatureConstants.ExclusiveC14n;
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

        // multi-transform case, inefficient path
        internal override object Process(XmlTokenStreamReader reader)
        {
            if (reader == null)
                throw LogHelper.LogArgumentNullException(nameof(reader));

            return CanonicalizationDriver.GetMemoryStream(reader, IncludeComments, _inclusivePrefixes);
        }

        internal override byte[] ProcessAndDigest(XmlTokenStreamReader reader, HashAlgorithm hash)
        {
            if (reader == null)
                LogHelper.LogArgumentNullException(nameof(reader));

            if (hash == null)
                LogHelper.LogArgumentNullException(nameof(hash));

            var stream = new MemoryStream();
            reader.MoveToContent();
            WriteCanonicalStream(stream, reader, IncludeComments, _inclusivePrefixes);
            stream.Flush();
            stream.Position = 0;
            return hash.ComputeHash(stream);
        }

        public static void WriteCanonicalStream(Stream canonicalStream, XmlTokenStreamReader reader, bool includeComments, string[] inclusivePrefixes)
        {
            XmlDictionaryWriter writer = XmlDictionaryWriter.CreateTextWriter(Stream.Null);
            if (inclusivePrefixes != null)
            {
                // Add a dummy element at the top and populate the namespace
                // declaration of all the inclusive prefixes.
                writer.WriteStartElement("a", reader.LookupNamespace(string.Empty));
                for (int i = 0; i < inclusivePrefixes.Length; ++i)
                {
                    string ns = reader.LookupNamespace(inclusivePrefixes[i]);
                    if (ns != null)
                    {
                        writer.WriteXmlnsAttribute(inclusivePrefixes[i], ns);
                    }
                }
            }

            writer.StartCanonicalization(canonicalStream, includeComments, inclusivePrefixes);
            reader.XmlTokens.WriteTo(writer);

            writer.Flush();
            writer.EndCanonicalization();

            if (inclusivePrefixes != null)
                writer.WriteEndElement();
#if DESKTOPNET45
            // TODO - what to use for net 1.4
            writer.Close();
#endif
        }

        public override void ReadFrom(XmlDictionaryReader reader, bool preserveComments)
        {
            XmlUtil.CheckReaderOnEntry(reader, _elementName, XmlSignatureConstants.Namespace, true);

            _prefix = reader.Prefix;
            bool isEmptyElement = reader.IsEmptyElement;
            Algorithm = reader.GetAttribute(XmlSignatureConstants.Attributes.Algorithm, null);
            if (string.IsNullOrEmpty(Algorithm))
                throw XmlUtil.LogReadException(LogMessages.IDX21013, XmlSignatureConstants.Elements.Signature, XmlSignatureConstants.Attributes.Algorithm);

            if (Algorithm == XmlSignatureConstants.ExclusiveC14nWithComments)
            {
                // to include comments in canonicalization, two conditions need to be met
                // 1. the Reference must be an xpointer.
                // 2. the transform must be #withComments
                IncludeComments = preserveComments && true;
            }
            else if (Algorithm == XmlSignatureConstants.ExclusiveC14n)
                IncludeComments = false;
            else
                XmlUtil.LogReadException(LogMessages.IDX21100, Algorithm, XmlSignatureConstants.ExclusiveC14nWithComments, XmlSignatureConstants.ExclusiveC14n);

            reader.Read();
            reader.MoveToContent();

            if (!isEmptyElement)
            {
                if (reader.IsStartElement(ExclusiveC14NConstants.InclusiveNamespaces, ExclusiveC14NConstants.Namespace))
                {
                    reader.MoveToStartElement(ExclusiveC14NConstants.InclusiveNamespaces, ExclusiveC14NConstants.Namespace);
                    _inclusiveListElementPrefix = reader.Prefix;
                    bool emptyElement = reader.IsEmptyElement;

                    // We treat PrefixList as optional Attribute.
                    InclusiveNamespacesPrefixList = reader.GetAttribute(ExclusiveC14NConstants.PrefixList, null);
                    reader.Read();
                    if (!emptyElement)
                        reader.ReadEndElement();
                }

                // </Transform>
                reader.MoveToContent();
                reader.ReadEndElement();
            }
        }

        public override void WriteTo(XmlDictionaryWriter writer)
        {
            writer.WriteStartElement(_prefix, _elementName, XmlSignatureConstants.Namespace);
            writer.WriteAttributeString(XmlSignatureConstants.Attributes.Algorithm, null, Algorithm);
            if (InclusiveNamespacesPrefixList != null)
            {
                writer.WriteStartElement(_inclusiveListElementPrefix, ExclusiveC14NConstants.InclusiveNamespaces, ExclusiveC14NConstants.Namespace);
                writer.WriteAttributeString(ExclusiveC14NConstants.PrefixList, null, InclusiveNamespacesPrefixList);
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
