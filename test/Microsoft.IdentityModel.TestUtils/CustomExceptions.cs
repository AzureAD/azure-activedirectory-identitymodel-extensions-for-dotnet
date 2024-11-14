// Copyright (c) Microsoft Corporation. All rights reserved.
// Licensed under the MIT License.

using System;
using Microsoft.IdentityModel.Tokens;

#nullable enable
namespace Microsoft.IdentityModel.TestUtils
{
    internal class CustomSecurityTokenInvalidIssuerException : SecurityTokenInvalidIssuerException
    {
        public CustomSecurityTokenInvalidIssuerException(string message)
            : base(message)
        {
        }
    }

    internal class CustomSecurityTokenException : SystemException
    {
        public CustomSecurityTokenException(string message)
            : base(message)
        {
        }
    }
}
#nullable restore
