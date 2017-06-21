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

namespace Microsoft.IdentityModel.Xml
{
    /// <summary>
    /// Log messages and codes for XmlProcessing
    /// Range: IDX21010 - IDX21200
    /// </summary>
    internal static class LogMessages
    {
#pragma warning disable 1591

        // Xml reading
        internal const string IDX20001 = "IDX10001: The value of this argument must fall within the range {0} to {1}.";
        internal const string IDX21010 = "IDX21010: Unable to read xml. Expecting XmlReader to be at element: '{0}', found 'Empty Element'";
        internal const string IDX21011 = "IDX21011: Unable to read xml. Expecting XmlReader to be at ns.element: '{0}.{1}', found: '{2}.{3}'.";
        internal const string IDX21012 = "IDX21012: Unable to read xml. While reading '{0}', This node was not expected: '{1}'.";
        internal const string IDX21013 = "IDX21013: Unable to read xml. While reading element '{0}', Required attribute was not found : '{1}'.";
        internal const string IDX21014 = "IDX21014: Unable to read xml. A SignedInfo reference must have at least 1 transform.";
        internal const string IDX21015 = "IDX21015: Only a single '{0}' element is supported. Found more than one.";
        internal const string IDX21016 = "IDX21016: Exception thrown while reading '{0}'. See inner exception for more details.";
        internal const string IDX21017 = "IDX21017: Exception thrown while reading '{0}'. Caught exception: '{1}'.";
        internal const string IDX21018 = "IDX21018: Unable to read xml. A Reference contains an unknown transform '{0}'.";
        internal const string IDX21019 = "IDX21019: Unable to read xml. A second <Signature> element was found. The EnvelopedSignatureReader can only process one <Signature>.";
        internal const string IDX21020 = "IDX21020: Unable to read xml. A second <Reference> element was found. The EnvelopedSignatures can only have one <Reference>.";
        internal const string IDX21021 = "IDX21021: Unable to read xml. Expecting XmlReader to be at element: '{0}', found: '{1}'.";
        internal const string IDX21022 = "IDX21022: Unable to read xml. Expecting XmlReader to be at a StartElement, NodeType is: '{0}'.";
        internal const string IDX21023 = "UnsupportedNodeTypeInReader, base.InnerReader.NodeType, base.InnerReader.Name";

        // xml structure, supported exceptions
        internal const string IDX21100 = "IDX21100: Unable to process the <Signature> element. This cannonizalization method is not supported: '{0}'. Supported methods are: '{1}', '{2}'.";
        internal const string IDX21101 = "IDX21101: An EnvelopedSignature must have a <Reference> element. None were found.";
        internal const string IDX21102 = "IDX21102: The reader passed to the {0}, must be pointing to a StartElement.";
        internal const string IDX21103 = "IDX21103: EnvelopedSignature must have exactly 1 reference. Found: '{0}'.";

        // signature validation
        internal const string IDX21200 = "IDX21200: The 'Signature' did not validate.";
        internal const string IDX21201 = "IDX21201: The 'Reference' did not validate: '{0}'.";
        internal const string IDX21202 = "IDX21202: A reference was included: '{0}'.";
        internal const string IDX21203 = "IDX21203: '{0}.CreateForVerifying' returned null for key: '{1}', signatureAlgorithm: '{2}'.";
        internal const string IDX21204 = "IDX21204: 'Canonicalization algorithm is not supported: '{0}'.";
        internal const string IDX21205 = "IDX21205: 'At least one reference is required";

        // logging messages
        internal const string IDX21300 = "IDX21300: KeyInfo skipped unknown element: '{0}'.";

        // Xml writting
        internal const string IDX21400 = "IDX21400: Unable to write xml. XmlTokenBuffer is empty.";

#pragma warning restore 1591
    }
}
