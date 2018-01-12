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
using static Microsoft.IdentityModel.Logging.LogHelper;

namespace Microsoft.IdentityModel.Tokens.Xml
{
    /// <summary>
    /// Represents Canonicalization algorithms found in &lt;SignedInfo> and in &lt;Reference>.
    /// </summary>
    public sealed class ExclusiveCanonicalizationTransform : CanonicalizingTransfrom
    {
        /// <summary>
        /// Initializes an instance of <see cref="ExclusiveCanonicalizationTransform"/>.
        /// </summary>
        /// <param name="includeComments">controls if the transform will include comments.</param>
        public ExclusiveCanonicalizationTransform(bool includeComments)
        {
            IncludeComments = includeComments;
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

        /// <summary>
        /// Applies a canonicalization transform over a set of XML nodes and computes the hash value.
        /// </summary>
        /// <param name="tokenStream">the set of XML nodes to transform.</param>
        /// <param name="hash">the hash algorithm to apply.</param>
        /// <returns>the hash of the transformed octets.</returns>
        public override byte[] ProcessAndDigest(XmlTokenStream tokenStream, HashAlgorithm hash)
        {
            if (tokenStream == null)
                throw LogArgumentNullException(nameof(tokenStream));

            if (hash == null)
                throw LogArgumentNullException(nameof(hash));

            using (var stream = new MemoryStream())
            {
                WriteCanonicalStream(stream, tokenStream, IncludeComments);
                stream.Flush();
                return hash.ComputeHash(stream.ToArray());
            }
        }

        /// <summary>
        /// Writes the Canonicalized XML into the stream.
        /// </summary>
        /// <param name="stream"><see cref="Stream"/>that will receive the canonicalized XML.</param>
        /// <param name="tokenStream"><see cref="XmlReader"/>that is positioned at the XML to canonicalized.</param>
        /// <param name="includeComments">controls if comments are included in the canonicalized XML.</param>
        /// <exception cref="ArgumentNullException">if 'stream' is null.</exception>
        /// <exception cref="ArgumentNullException">if 'reader' is null.</exception>
        public static void WriteCanonicalStream(Stream stream, XmlTokenStream tokenStream, bool includeComments)
        {
            if (stream == null)
                throw LogArgumentNullException(nameof(stream));

            if (tokenStream == null)
                throw LogArgumentNullException(nameof(tokenStream));

            using (var writer = XmlDictionaryWriter.CreateTextWriter(Stream.Null))
            {
                writer.StartCanonicalization(stream, includeComments, null);
                tokenStream.WriteTo(writer);
                writer.EndCanonicalization();
                writer.Flush();
            }
        }
    }
}
