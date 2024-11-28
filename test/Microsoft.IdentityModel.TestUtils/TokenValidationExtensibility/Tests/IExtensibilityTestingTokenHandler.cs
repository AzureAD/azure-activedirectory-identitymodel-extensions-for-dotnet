// Copyright (c) Microsoft Corporation. All rights reserved.
// Licensed under the MIT License.

using System.Threading;
using System.Threading.Tasks;
using Microsoft.IdentityModel.JsonWebTokens;
using Microsoft.IdentityModel.Tokens;
using Microsoft.IdentityModel.Tokens.Saml;
using Microsoft.IdentityModel.Tokens.Saml2;

namespace Microsoft.IdentityModel.TestUtils.TokenValidationExtensibility.Tests
{
    // This interface is used to test the extensibility of the ValidateTokenAsync method
    // in the JsonWebTokenHandler, SamlSecurityTokenHandler, and Saml2SecurityTokenHandler classes,
    // since the ValidateTokenAsync method with ValidationParameters is not part of any shared interface.
    internal interface IExtensibilityTestingTokenHandler
    {
        Task<ValidationResult<ValidatedToken>> ValidateTokenAsync(
            SecurityToken token,
            ValidationParameters validationParameters,
            CallContext callContext,
            CancellationToken cancellationToken);

        SecurityToken CreateToken(SecurityTokenDescriptor tokenDescriptor);
    }

    // Because the ValidateTokenAsync method in the token handler subclasses is internal, we need
    // to create classes that implement the IValidateTokenAsyncResult interface to use in tests.
    internal class JsonWebTokenHandlerWithResult : IExtensibilityTestingTokenHandler
    {
        private readonly JsonWebTokenHandler _handler = new JsonWebTokenHandler();

        public JsonWebTokenHandlerWithResult()
        {
        }

        public async Task<ValidationResult<ValidatedToken>> ValidateTokenAsync(
            SecurityToken token,
            ValidationParameters validationParameters,
            CallContext callContext,
            CancellationToken cancellationToken)
        {
            return await _handler.ValidateTokenAsync(token, validationParameters, callContext, cancellationToken);
        }

        public SecurityToken CreateToken(SecurityTokenDescriptor tokenDescriptor)
        {
            return _handler.ReadToken(_handler.CreateToken(tokenDescriptor));
        }
    }

    internal class SamlSecurityTokenHandlerWithResult : IExtensibilityTestingTokenHandler
    {
        private readonly SamlSecurityTokenHandler _handler = new SamlSecurityTokenHandler();

        public async Task<ValidationResult<ValidatedToken>> ValidateTokenAsync(
            SecurityToken token,
            ValidationParameters validationParameters,
            CallContext callContext,
            CancellationToken cancellationToken)
        {
            return await _handler.ValidateTokenAsync(token, validationParameters, callContext, cancellationToken);
        }

        public SecurityToken CreateToken(SecurityTokenDescriptor tokenDescriptor)
        {
            SamlSecurityToken token = (SamlSecurityToken)_handler.CreateToken(tokenDescriptor);
            // SamlSecurityTokenHandler.CreateToken does not set correctly the signature on the token.
            // Reading the token from the CanonicalString will set the signature correctly.
            return _handler.ReadToken(token.Assertion.CanonicalString);
        }
    }

    internal class Saml2SecurityTokenHandlerWithResult : IExtensibilityTestingTokenHandler
    {
        private readonly Saml2SecurityTokenHandler _handler = new Saml2SecurityTokenHandler();

        public async Task<ValidationResult<ValidatedToken>> ValidateTokenAsync(
            SecurityToken token,
            ValidationParameters validationParameters,
            CallContext callContext,
            CancellationToken cancellationToken)
        {
            return await _handler.ValidateTokenAsync(token, validationParameters, callContext, cancellationToken);
        }

        public SecurityToken CreateToken(SecurityTokenDescriptor tokenDescriptor)
        {
            Saml2SecurityToken token = (Saml2SecurityToken)_handler.CreateToken(tokenDescriptor);
            // SamlSecurityTokenHandler.CreateToken does not set correctly the signature on the token.
            // Reading the token from the CanonicalString will set the signature correctly.
            return _handler.ReadToken(token.Assertion.CanonicalString);
        }
    }
}
