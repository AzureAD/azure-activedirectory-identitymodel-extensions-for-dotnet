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

namespace System.IdentityModel.Tokens
{
#if DESKTOPNET45
        [Serializable]
#endif
    /// <summary>
    /// This exception is thrown when a security token contained a key identifier but the key was not found by the runtime.
    /// </summary>
    public class SecurityTokenSignatureKeyNotFoundException : SecurityTokenInvalidSignatureException
    {
        /// <summary>
        /// Initializes a new instance of the <see cref="SecurityTokenSignatureKeyNotFoundException"/> class.
        /// </summary>
        public SecurityTokenSignatureKeyNotFoundException()
            : base()
        {
        }

        /// <summary>
        /// Initializes a new instance of the <see cref="SecurityTokenSignatureKeyNotFoundException"/> class.
        /// </summary>
        /// <param name="message">Addtional information to be included in the exception and displayed to user.</param>
        public SecurityTokenSignatureKeyNotFoundException(String message)
            : base(message)
        {
        }

        /// <summary>
        /// Initializes a new instance of the <see cref="SecurityTokenSignatureKeyNotFoundException"/> class.
        /// </summary>
        /// <param name="message">Addtional information to be included in the exception and displayed to user.</param>
        /// <param name="innerException">A <see cref="Exception"/> that represents the root cause of the exception.</param>
        public SecurityTokenSignatureKeyNotFoundException(String message, Exception innerException)
            : base(message, innerException)
        {
        }
#if DESKTOPNET45
        /// <summary>
        /// Initializes a new instance of the <see cref="SecurityTokenSignatureKeyNotFoundException"/> class.
        /// </summary>
        /// <param name="info">the <see cref="SerializationInfo"/> that holds the serialized object data.</param>
        /// <param name="context">The contextual information about the source or destination.</param>
        protected SecurityTokenSignatureKeyNotFoundException(SerializationInfo info, StreamingContext context)
            : base(info, context)
        {
        }
#endif
    }
}
