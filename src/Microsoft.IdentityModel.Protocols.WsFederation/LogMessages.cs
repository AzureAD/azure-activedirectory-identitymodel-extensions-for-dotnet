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

namespace Microsoft.IdentityModel.Protocols.WsFederation
{
    /// <summary>
    /// Log messages and codes
    /// </summary>
    internal static class LogMessages
    {
#pragma warning disable 1591
        // general
        internal const string IDX10000 = "IDX10000: The parameter '{0}' cannot be a 'null' or an empty object.";

        // wsfederation messages
        internal const string IDX10900 = "IDX10900: Building wsfederation message from query string: '{0}'.";
        internal const string IDX10901 = "IDX10901: Building wsfederation message from uri: '{0}'.";
        internal const string IDX10902 = "IDX10902: Token is not found in wresult";

        // xml metadata messages
        internal const string IDX13000 = "IDX13000: Exception thrown while reading WsFedereationMetadata. Element '{0}'. Caught exception: '{1}'.";
        internal const string IDX13001 = "IDX13001: entityID attribute is not found in EntityDescriptor element in metadata file.";
        internal const string IDX13002 = "IDX13002: Current name '{0} and namespace '{1}' do not match the expected name '{2}' and namespace '{3}'.";
        internal const string IDX13003 = "IDX13003: Token reference address is missing in SecurityTokenServiceEndpoint in metadata file.";
        internal const string IDX13004 = "IDX13004: Security token type role descriptor is expected.";
        internal const string IDX13005 = "IDX13005: Key descriptor for signing is expected.";
        internal const string IDX13006 = "IDX13006: Key descriptor for signing is missing in security token service type RoleDescriptor.";
        internal const string IDX13007 = "IDX13007: Token endpoint is missing in security token service type RoleDescriptor.";
        internal const string IDX13008 = "IDX13008: 'Use' attribute is missing in KeyDescriptor.";
        internal const string IDX13009 = "IDX13009: The expected value for attribute '{0}' is '{1}', but the current one is '{2}'.";
#pragma warning restore 1591
    }
}
