// Copyright (c) Microsoft Corporation. All rights reserved.
// Licensed under the MIT License.

using System;
using System.Collections.Generic;
using System.IdentityModel.Tokens.Jwt;
using Microsoft.IdentityModel.Tokens;
using Microsoft.IdentityModel.Tokens.Saml;
using Microsoft.IdentityModel.Tokens.Saml2;

namespace Microsoft.IdentityModel.TestUtils
{
    /// <summary>
    /// Main purpose of this code is to serve up ValidationDelegates for TokenValidatationParameters
    /// </summary>
    public static class ValidationDelegates
    {
        public static AlgorithmValidator AlgorithmValidatorBuilder(bool result)
        {
            return (string algorithm, SecurityKey securityKey, SecurityToken securityToken, TokenValidationParameters validationParameters) => result;
        }

        public static bool AudienceValidatorReturnsFalse(IEnumerable<string> audiences, SecurityToken token, TokenValidationParameters validationParameters)
        {
            return false;
        }

        public static bool AudienceValidatorReturnsTrue(IEnumerable<string> audiences, SecurityToken token, TokenValidationParameters validationParameters)
        {
            return true;
        }

        public static bool AudienceValidatorThrows(IEnumerable<string> audiences, SecurityToken token, TokenValidationParameters validationParameters)
        {
            throw new SecurityTokenInvalidAudienceException($"{typeof(ValidationDelegates)}.AudienceValidatorThrows");
        }

        public static bool IssuerSecurityKeyValidatorReturnsFalse(SecurityKey securityKey, SecurityToken securityToken, TokenValidationParameters validationParameters)
        {
            return false;
        }

        public static bool IssuerSecurityKeyValidatorReturnsTrue(SecurityKey securityKey, SecurityToken securityToken, TokenValidationParameters validationParameters)
        {
            return true;
        }

        public static bool IssuerSecurityKeyValidatorThrows(SecurityKey securityKey, SecurityToken securityToken, TokenValidationParameters validationParameters)
        {
            throw new SecurityTokenInvalidSigningKeyException("IssuerSecurityKeyValidatorThrows");
        }

        public static string IssuerValidatorEcho(string issuer, SecurityToken token, TokenValidationParameters validationParameters)
        {
            return issuer;
        }

        public static string IssuerValidatorReturnsDifferentIssuer(string issuer, SecurityToken token, TokenValidationParameters validationParameters)
        {
            return "DifferentIssuer";
        }

        public static string IssuerValidatorReturnsNull(string issuer, SecurityToken token, TokenValidationParameters validationParameters)
        {
            return null;
        }

        public static string IssuerValidatorThrows(string issuer, SecurityToken token, TokenValidationParameters validationParameters)
        {
            throw new SecurityTokenInvalidIssuerException("IssuerValidatorThrows");
        }

        public static bool LifetimeValidatorReturnsFalse(DateTime? expires, DateTime? notBefore, SecurityToken token, TokenValidationParameters validationParameters)
        {
            return false;
        }

        public static bool LifetimeValidatorReturnsTrue(DateTime? expires, DateTime? notBefore, SecurityToken token, TokenValidationParameters validationParameters)
        {
            return true;
        }

        public static bool LifetimeValidatorThrows(DateTime? expires, DateTime? notBefore, SecurityToken token, TokenValidationParameters validationParameters)
        {
            throw new SecurityTokenInvalidLifetimeException("LifetimeValidatorThrows");
        }

        public static SecurityToken SignatureValidatorReturnsJwtTokenAsIs(string token, TokenValidationParameters validationParameters)
        {
            return new JwtSecurityToken(token);
        }

        public static SecurityToken SignatureValidatorReturnsNull(string token, TokenValidationParameters validationParameters)
        {
            return null;
        }

        public static SecurityToken SignatureValidatorThrows(string token, TokenValidationParameters validationParameters)
        {
            throw new SecurityTokenInvalidSignatureException("SignatureValidatorThrows");
        }

        public static SecurityToken TokenReaderReturnsJwtSecurityToken(string token, TokenValidationParameters validationParameters)
        {
            return new JwtSecurityToken(token);
        }

        public static SecurityToken TokenReaderReturnsIncorrectSecurityTokenType(string token, TokenValidationParameters validationParameters)
        {
            return new DerivedSecurityToken();
        }

        public static SecurityToken TokenReaderReturnsNull(string token, TokenValidationParameters validationParameters)
        {
            return null;
        }

        public static SecurityToken TokenReaderThrows(string token, TokenValidationParameters validationParameters)
        {
            throw new SecurityTokenInvalidSignatureException("TokenReaderThrows");
        }

        public static bool TokenReplayValidatorReturnsTrue(DateTime? expires, string token, TokenValidationParameters validationParameters)
        {
            return true;
        }

        public static bool TokenReplayValidatorReturnsFalse(DateTime? expires, string token, TokenValidationParameters validationParameters)
        {
            return false;
        }

        public static bool TokenReplayValidatorChecksExpirationTimeJwt(DateTime? expires, string token, TokenValidationParameters validationParameters)
        {
            if (expires == null)
                return false;

            var jwtToken = new JwtSecurityTokenHandler().ReadToken(token);
            return jwtToken.ValidTo == expires;
        }

        public static bool TokenReplayValidatorChecksExpirationTimeSaml(DateTime? expires, string token, TokenValidationParameters validationParameters)
        {
            if (expires == null)
                return false;

            var samlToken = (SamlSecurityToken) new SamlSecurityTokenHandler().ReadToken(token);
            return samlToken.Assertion.Conditions.NotOnOrAfter == expires;
        }

        public static bool TokenReplayValidatorChecksExpirationTimeSaml2(DateTime? expires, string token, TokenValidationParameters validationParameters)
        {
            if (expires == null)
                return false;

            var saml2Token = (Saml2SecurityToken) new Saml2SecurityTokenHandler().ReadToken(token);
            return saml2Token.Assertion.Conditions.NotOnOrAfter == expires;
        }

        public static bool TokenReplayValidatorThrows(DateTime? expires, string token, TokenValidationParameters validationParameters)
        {
            throw new SecurityTokenReplayDetectedException("TokenReplayValidatorThrows");
        }
    }
}
