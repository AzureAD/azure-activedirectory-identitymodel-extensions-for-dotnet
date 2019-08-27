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

#pragma warning disable 1591

using System;
using Microsoft.IdentityModel.Logging;

namespace Microsoft.IdentityModel.Protocols.WsFed
{
    /// <summary>
    /// This class is used to represent a ContextItem found in the WsFed specification: http://docs.oasis-open.org/wsfed/federation/v1.2/os/ws-federation-1.2-spec-os.html .
    /// </summary>
    public class ContextItem
    {
        private string _name;
        private string _scope;
        private string _value;

        public ContextItem() { }

        // brentsch - TODO, it is contradictory to have setters that take null, but throw in constructors.
        public ContextItem(string name)
        {
            Name = name;
        }

        public ContextItem(string name, string value)
        {
            // [brentsch] - TODO check for absolute URI
            Name = name;
            Value = value;
        }

        public ContextItem(string name, string value, string scope)
        {
            // [brentsch] - TODO check for absolute URI
            Name = name;
            Value = value;
            Scope = scope;
        }

        /// <summary>
        /// Gets the name of the item.
        /// </summary>
        public string Name 
        {
            get => _name;
            set => _name = (string.IsNullOrEmpty(value)) ? throw LogHelper.LogArgumentNullException(nameof(Name)) : value; 
        }

        /// <summary>
        /// Gets the Scope of the scope.
        /// </summary>
        public string Scope
        {
            get => _scope;
            set => _scope = (string.IsNullOrEmpty(value)) ? throw LogHelper.LogArgumentNullException(nameof(Scope)) : value;
        }

        /// <summary>
        /// Gets the value of the value.
        /// </summary>
        public string Value
        {
            get => _value;
            set => _value = (string.IsNullOrEmpty(value)) ? throw LogHelper.LogArgumentNullException(nameof(Value)) : value;
        }
    }
}
