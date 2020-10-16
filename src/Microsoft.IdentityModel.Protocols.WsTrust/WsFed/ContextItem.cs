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

        /// <summary>
        /// Instantiates a empty <see cref="ContextItem"/>.
        /// </summary>
        public ContextItem() { }

        /// <summary>
        /// Instantiates a <see cref="ContextItem"/> with a name.
        /// </summary>
        /// <param name="name">the name of this <see cref="ContextItem"/>.</param>
        /// <exception cref="ArgumentNullException"> thrown if <paramref name="name"/> is null or empty.</exception>
        public ContextItem(string name)
        {
            Name = name;
        }

        /// <summary>
        /// Instantiates a <see cref="ContextItem"/> with a name and value.
        /// </summary>
        /// <param name="name">the name of this <see cref="ContextItem"/>.</param>
        /// <param name="value">the value of this <see cref="ContextItem"/>.</param>
        /// <exception cref="ArgumentNullException"> thrown if <paramref name="name"/> is null or empty.</exception>
        /// <exception cref="ArgumentNullException"> thrown if <paramref name="value"/> is null or empty.</exception>
        public ContextItem(string name, string value)
        {
            Name = name;
            Value = value;
        }

        /// <summary>
        /// Instantiates a <see cref="ContextItem"/> with a name, value and scope.
        /// </summary>
        /// <param name="name">the name of this <see cref="ContextItem"/>.</param>
        /// <param name="value">the value of this <see cref="ContextItem"/>.</param>
        /// <param name="scope">the value of this <see cref="ContextItem"/>.</param>
        /// <exception cref="ArgumentNullException"> thrown if <paramref name="name"/> is null or empty.</exception>
        /// <exception cref="ArgumentNullException"> thrown if <paramref name="value"/> is null or empty.</exception>
        /// <exception cref="ArgumentNullException"> thrown if <paramref name="scope"/> is null or empty.</exception>
        public ContextItem(string name, string value, string scope)
        {
            Name = name;
            Value = value;
            Scope = scope;
        }

        /// <summary>
        /// Gets or sets the Name of this <see cref="ContextItem"/>.
        /// </summary>
        /// <exception cref="ArgumentNullException"> thrown if value is null or empty.</exception>
        public string Name 
        {
            get => _name;
            set => _name = (string.IsNullOrEmpty(value)) ? throw LogHelper.LogArgumentNullException(nameof(Name)) : value; 
        }

        /// <summary>
        /// Gets or sets the Scope of this <see cref="ContextItem"/>.
        /// </summary>
        /// <exception cref="ArgumentNullException"> thrown if value is null or empty.</exception>
        public string Scope
        {
            get => _scope;
            set => _scope = (string.IsNullOrEmpty(value)) ? throw LogHelper.LogArgumentNullException(nameof(Scope)) : value;
        }

        /// <summary>
        /// Gets or sets the value of this <see cref="ContextItem"/>.
        /// </summary>
        /// <exception cref="ArgumentNullException"> thrown if value is null or empty.</exception>
        public string Value
        {
            get => _value;
            set => _value = (string.IsNullOrEmpty(value)) ? throw LogHelper.LogArgumentNullException(nameof(Value)) : value;
        }
    }
}
