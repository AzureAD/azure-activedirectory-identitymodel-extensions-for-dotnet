// Copyright (c) Microsoft Open Technologies, Inc. All rights reserved. See License.txt in the project root for license information.

using System;
using System.Runtime.Serialization;

namespace Microsoft.IdentityModel.Protocols
{
    [Serializable]
    public class OpenIdConnectException : Exception
    {
        public OpenIdConnectException()
        {
        }

        public OpenIdConnectException(String message)
            : base(message)
        {
        }

        public OpenIdConnectException(String message, Exception innerException)
            : base(message, innerException)
        {
        }

        protected OpenIdConnectException(SerializationInfo info, StreamingContext context)
            : base(info, context)
        {
        }
    }
}