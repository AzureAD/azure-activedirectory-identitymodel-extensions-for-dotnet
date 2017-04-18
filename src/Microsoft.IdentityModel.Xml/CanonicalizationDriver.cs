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

using System.IO;
using System.Xml;

namespace Microsoft.IdentityModel.Xml
{
    internal static class CanonicalizationDriver
    {
        public static MemoryStream GetMemoryStream(TokenStreamingReader reader, bool includeComments, string[] inclusivePrefixe)
        {
            MemoryStream stream = new MemoryStream();
            WriteTo(stream, reader, includeComments, inclusivePrefixe);
            stream.Seek(0, SeekOrigin.Begin);
            return stream;
        }

        public static void WriteTo(Stream canonicalStream, TokenStreamingReader reader, bool includeComments, string[] inclusivePrefixes)
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

            writer.Close();
        }
    }
}
