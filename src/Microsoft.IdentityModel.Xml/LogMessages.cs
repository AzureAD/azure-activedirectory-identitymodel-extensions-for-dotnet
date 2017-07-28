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

        // XML reading
        internal const string IDX20001 = "IDX10001: The value of this argument must fall within the range {0} to {1}.";
        internal const string IDX21010 = "IDX21010: Unable to read XML. Expecting XmlReader to be at element: '{0}', found 'Empty Element'";
        internal const string IDX21011 = "IDX21011: Unable to read XML. Expecting XmlReader to be at ns.element: '{0}.{1}', found: '{2}.{3}'.";
        internal const string IDX21012 = "IDX21012: Unable to read XML. While reading '{0}', This node was not expected: '{1}'.";
        internal const string IDX21013 = "IDX21013: Unable to read XML. While reading element '{0}', Required attribute was not found : '{1}'.";
        internal const string IDX21014 = "IDX21014: Unable to read XML. A SignedInfo reference must have at least 1 transform.";
        internal const string IDX21015 = "IDX21015: Only a single '{0}' element is supported. Found more than one.";
        internal const string IDX21016 = "IDX21016: Exception thrown while reading '{0}'. See inner exception for more details.";
        internal const string IDX21017 = "IDX21017: Exception thrown while reading '{0}'. Caught exception: '{1}'.";
        internal const string IDX21018 = "IDX21018: Unable to read XML. A Reference contains an unknown transform '{0}'.";
        internal const string IDX21019 = "IDX21019: Unable to read XML. A second <Signature> element was found. The EnvelopedSignatureReader can only process one <Signature>.";
        internal const string IDX21020 = "IDX21020: Unable to read XML. A second <Reference> element was found. The EnvelopedSignatures can only have one <Reference>.";
        internal const string IDX21021 = "IDX21021: Unable to read XML. Expecting XmlReader to be at element: '{0}', found: '{1}'.";
        internal const string IDX21022 = "IDX21022: Unable to read XML. Expecting XmlReader to be at a StartElement, NodeType is: '{0}'.";
        internal const string IDX21023 = "IDX21023: Unsupported NodeType: {0}.";
        internal const string IDX21024 = "IDX21024: Unable to read XML. Expecting XmlReader to be at element: '{0}', found: '{1}'.";
        internal const string IDX21025 = "IDX21025: Unable to read XML. Expecting XmlReader to be at EndElement: '{0}'. Found XmlNode 'type.name': '{1}.{2}'.";

        // XML structure, supported exceptions
        internal const string IDX21100 = "IDX21100: Unable to process the {0} element. This canonicalization method is not supported: '{1}'. Supported methods are: '{2}', '{3}', '{4}'.";
        internal const string IDX21101 = "IDX21101: An EnvelopedSignature must have a <Reference> element. None were found.";
        internal const string IDX21102 = "IDX21102: The reader must be pointing to a StartElement. NodeType is: '{0}'.";
        internal const string IDX21103 = "IDX21103: EnvelopedSignature must have exactly 1 reference. Found: '{0}'.";
        internal const string IDX21105 = "IDX21105: Transform must specify an algorithm none was found.";
        internal const string IDX21106 = "IDX21106: ExclusiveCanonicalizationTransform must be the last transform.";
        internal const string IDX21107 = "IDX21107: 'InclusiveNamespaces' is not supported.";

        // signature validation
        internal const string IDX21200 = "IDX21200: The 'Signature' did not validate. CryptoProviderFactory: '{0}', SecurityKey: '{1}'.";
        internal const string IDX21201 = "IDX21201: The 'Reference' did not validate: '{0}'.";
        internal const string IDX21202 = "IDX21202: The Reference does not have a XmlTokenStream set: '{0}'.";
        internal const string IDX21203 = "IDX21203: The CryptoProviderFactory: '{0}', CreateForVerifying returned null for key: '{1}', SignatureMethod: '{2}'.";
        internal const string IDX21204 = "IDX21204: Canonicalization algorithm is not supported: '{0}'. Supported methods are: '{1}', '{2}'.";
        internal const string IDX21205 = "IDX21205: At least one reference is required.";
        internal const string IDX21206 = "IDX21206: The reference '{0}' did not contain a digest.";
        internal const string IDX21207 = "IDX21207: SignatureMethod is not supported: '{0}'. CryptoProviderFactory: '{1}'.";
        internal const string IDX21208 = "IDX21208: DigestMethod is not supported: '{0}'. CryptoProviderFactory: '{1}'.";
        internal const string IDX21209 = "IDX21209: The CryptoProviderFactory: '{0}', CreateHashAlgorithm, returned null for DigestMethod: '{1}'.";
        internal const string IDX21210 = "IDX21210: The TransformFactory: '{0}', does not support the transform: '{1}'.";
        internal const string IDX21211 = "IDX21211: The TransfromFactory: '{0}', GetTransform, returned null for Transform: '{1}'.";
        internal const string IDX21212 = "IDX21212: The TransfromFactory: '{0}', GetCanonicalizingTransform, returned null for Transform: '{1}'.";

        // logging messages
        internal const string IDX21300 = "IDX21300: KeyInfo skipped unknown element: '{0}'.";

        // XML writing
        internal const string IDX21400 = "IDX21400: Unable to write XML. XmlTokenBuffer is empty.";
        internal const string IDX21401 = "IDX21401: Unable to write XML. {0}.{1} is null or empty.";
        internal const string IDX21403 = "IDX21402: Unable to write XML. One of the values in Reference.Transforms is null or empty.";
        internal const string IDX21404 = "IDX21401: Unable to write XML. Signature.SignedInfo is null.";
        internal const string IDX21405 = "IDX21405: Unable to write XML. SignedInfo.Reference is null.";
#pragma warning restore 1591
    }
}
