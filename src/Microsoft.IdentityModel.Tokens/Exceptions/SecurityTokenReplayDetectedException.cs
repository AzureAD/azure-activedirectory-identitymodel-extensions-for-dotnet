//-----------------------------------------------------------------------
// Copyright (c) Microsoft Open Technologies, Inc.
// All Rights Reserved
// Apache License 2.0
//
// Licensed under the Apache License, Version 2.0 (the "License");
// you may not use this file except in compliance with the License.
// You may obtain a copy of the License at
// 
// http://www.apache.org/licenses/LICENSE-2.0
// 
// Unless required by applicable law or agreed to in writing, software
// distributed under the License is distributed on an "AS IS" BASIS,
// WITHOUT WARRANTIES OR CONDITIONS OF ANY KIND, either express or implied.
// See the License for the specific language governing permissions and
// limitations under the License.
//-----------------------------------------------------------------------

using System;

namespace System.IdentityModel.Tokens
{
#if DESKTOPNET45
        [Serializable]
#endif
    /// <summary>
    /// Throw this exception when a received Security Token has been replayed.
    /// </summary>
    public class SecurityTokenReplayDetectedException : SecurityTokenValidationException
    {
        /// <summary>
        /// Initializes a new instance of  <see cref="SecurityTokenReplayDetectedException"/>
        /// </summary>
        public SecurityTokenReplayDetectedException()
            : base("SecurityToken replay detected")
        {
        }

        /// <summary>
        /// Initializes a new instance of  <see cref="SecurityTokenReplayDetectedException"/>
        /// </summary>
        public SecurityTokenReplayDetectedException(string message)
            : base(message)
        {
        }

        /// <summary>
        /// Initializes a new instance of  <see cref="SecurityTokenReplayDetectedException"/>
        /// </summary>
        public SecurityTokenReplayDetectedException(string message, Exception inner)
            : base(message, inner)
        {
        }

#if DESKTOPNET45
        /// <summary>
        /// Initializes a new instance of the <see cref="SecurityTokenReplayDetectedException"/> class.
        /// </summary>
        /// <param name="info">the <see cref="SerializationInfo"/> that holds the serialized object data.</param>
        /// <param name="context">The contextual information about the source or destination.</param>
        protected SecurityTokenReplayDetectedException(SerializationInfo info, StreamingContext context)
            : base(info, context)
        {
        }
#endif

    }
}
