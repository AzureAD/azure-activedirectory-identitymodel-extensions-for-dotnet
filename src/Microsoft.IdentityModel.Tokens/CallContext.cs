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
using System.Collections.Generic;
using System.Collections.ObjectModel;

namespace Microsoft.IdentityModel.Tokens
{
    /// <summary>
    /// An opaque context used to store work when working with authentication artifacts.
    /// </summary>
    public class CallContext
    {
        /// <summary>
        /// Instantiates a new <see cref="CallContext"/> with a default activityId.
        /// </summary>
        public CallContext()
        {
        }

        /// <summary>
        /// Instantiates a new <see cref="CallContext"/> with an activityId.
        /// </summary>
        public CallContext(Guid activityId)
        {
            ActivityId = activityId;
        }

        /// <summary>
        /// Gets or set a <see cref="Guid"/> that will be used in the call to EventSource.SetCurrentThreadActivityId before logging.
        /// </summary>
        public Guid ActivityId { get; set; } = Guid.Empty;

        /// <summary>
        /// Gets or sets a boolean controlling if logs are written into the context.
        /// Useful when debugging.
        /// </summary>
        public bool CaptureLogs { get; set; } = false;

        /// <summary>
        /// The collection of logs associated with a request. Use <see cref="CaptureLogs"/> to control capture.
        /// </summary>
        public ICollection<string> Logs { get; private set; } = new Collection<string>();

        /// <summary>
        /// Gets or sets an <see cref="IDictionary{String, Object}"/> that enables custom extensibility scenarios.
        /// </summary>
        public IDictionary<string, object> PropertyBag { get; set; }
    }
}
