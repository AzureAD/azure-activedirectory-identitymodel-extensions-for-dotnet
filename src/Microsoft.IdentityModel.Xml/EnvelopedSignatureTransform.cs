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

using static Microsoft.IdentityModel.Logging.LogHelper;
using static Microsoft.IdentityModel.Xml.XmlSignatureConstants;

namespace Microsoft.IdentityModel.Xml
{
    /// <summary>
    /// Defines a XML transform that removes the XML nodes associated with the Signature.
    /// </summary>
    public sealed class EnvelopedSignatureTransform : Transform
    {
        /// <summary>
        /// Creates an EnvelopedSignatureTransform
        /// </summary>
        public EnvelopedSignatureTransform()
        {
        }

        /// <summary>
        /// Sets the reader to exclude the &lt;Signature> element
        /// </summary>
        /// <param name="tokenStream"><see cref="XmlTokenStream"/>to process.</param>
        /// <returns><see cref="XmlTokenStreamReader"/>with exclusion set.</returns>
        public override XmlTokenStream Process(XmlTokenStream tokenStream)
        {
            if (tokenStream == null)
                LogArgumentNullException(nameof(tokenStream));

            tokenStream.SetElementExclusion(Elements.Signature, Namespace);
            return tokenStream;
        }
    }
}
