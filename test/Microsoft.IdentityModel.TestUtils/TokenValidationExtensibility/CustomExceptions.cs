// Copyright (c) Microsoft Corporation. All rights reserved.
// Licensed under the MIT License.

using System;
using Microsoft.IdentityModel.Tokens;

#nullable enable
namespace Microsoft.IdentityModel.TestUtils
{
    internal class CustomSecurityTokenException : SecurityTokenException
    {
        public CustomSecurityTokenException(string message, Exception? innerException)
            : base(message, innerException)
        {
        }
    }

    internal class CustomSecurityTokenInvalidIssuerException : SecurityTokenInvalidIssuerException
    {
        public CustomSecurityTokenInvalidIssuerException(string message, Exception? innerException)
            : base(message, innerException)
        {
        }
    }

    internal class CustomSecurityTokenInvalidAudienceException : SecurityTokenInvalidAudienceException
    {
        public CustomSecurityTokenInvalidAudienceException(string message, Exception? innerException)
            : base(message, innerException)
        {
        }
    }

    internal class CustomSecurityTokenInvalidLifetimeException : SecurityTokenInvalidLifetimeException
    {
        public CustomSecurityTokenInvalidLifetimeException(string message, Exception? innerException)
            : base(message, innerException)
        {
        }
    }

    internal class CustomSecurityTokenInvalidSignatureException : SecurityTokenInvalidSignatureException
    {
        public CustomSecurityTokenInvalidSignatureException(string message, Exception? innerException)
            : base(message, innerException)
        {
        }
    }

    internal class CustomSecurityTokenInvalidAlgorithmException : SecurityTokenInvalidAlgorithmException
    {
        public CustomSecurityTokenInvalidAlgorithmException(string message, Exception? innerException)
            : base(message, innerException)
        {
        }
    }

    internal class CustomSecurityTokenInvalidTypeException : SecurityTokenInvalidTypeException
    {
        public CustomSecurityTokenInvalidTypeException(string message, Exception? innerException)
            : base(message, innerException)
        {
        }
    }

    internal class CustomSecurityTokenInvalidSigningKeyException : SecurityTokenInvalidSigningKeyException
    {
        public CustomSecurityTokenInvalidSigningKeyException(string message, Exception? innerException)
            : base(message, innerException)
        {
        }
    }

    internal class CustomSecurityTokenReplayDetectedException : SecurityTokenReplayDetectedException
    {
        public CustomSecurityTokenReplayDetectedException(string message, Exception? innerException)
            : base(message, innerException)
        {
        }
    }

    internal class CustomSecurityTokenDecryptionFailedException : SecurityTokenDecryptionFailedException
    {
        public CustomSecurityTokenDecryptionFailedException(string message, Exception? innerException)
            : base(message, innerException)
        {
        }
    }
}
#nullable restore
