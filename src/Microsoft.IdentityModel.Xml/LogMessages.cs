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
        // general
        internal const string IDX11000 = "IDX11000: The parameter '{0}' cannot be a 'null' or an empty object.";


        // Xml reading
        internal const string IDX21010 = "IDX21010: Unable to read xml. Expecting XmlReader to be at element: '{0}', found 'Empty Element'";
        internal const string IDX21011 = "IDX21011: Unable to read xml. Expecting XmlReader to be at element: '{0}', found: '{1}'.";
        internal const string IDX21012 = "IDX21012: Unable to read xml. While reading '{0}', This node was not expected: '{1}'.";
        internal const string IDX21013 = "IDX21013: Unable to read xml. While reading '{0}', Required attribute was not found : '{1}'.";
        internal const string IDX21014 = "IDX21014: Unable to read xml. Required element was not found : '{0}:{1}'. Reader is positioned at: '{2}'.";

        // NotSupported Exceptions
        internal const string IDX21100 = "IDX21100: Unable to process signature. This cannonizalization method is not supported: '{0}'. Supported methods are: '{1}', '{2}'.";
        internal const string IDX21101 = "IDX21101: EnvelopedSignature must have exactly 1 reference. Found: '{0}'.";
        internal const string IDX21102 = "IDX21102: The reader passed to the {0}, must be pointing to a StartElement.";

#pragma warning restore 1591
    }
}
