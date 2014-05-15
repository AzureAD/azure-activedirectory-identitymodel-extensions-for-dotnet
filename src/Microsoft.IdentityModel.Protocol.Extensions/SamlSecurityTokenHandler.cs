// Copyright (c) Microsoft Open Technologies, Inc. All rights reserved. See License.txt in the project root for license information.

using System;
using System.Collections.Generic;
using System.Collections.ObjectModel;
using System.Globalization;
using System.IdentityModel.Selectors;
using System.IdentityModel.Tokens;
using System.IO;
using System.Security.Claims;
using System.Xml;

namespace Microsoft.IdentityModel.Extensions
{
    /// <summary>
    /// A derived <see cref="System.IdentityModel.Tokens.Saml2SecurityTokenHandler"/> that implements ISecurityTokenValidator, 
    /// which supports validating tokens passed as strings using <see cref="TokenValidationParameters"/>.
    /// </summary>
    ///     
    public class SamlSecurityTokenHandler : System.IdentityModel.Tokens.SamlSecurityTokenHandler, ISecurityTokenValidator
    {
        private string _authenticationType = AuthenticationTypes.Federation;
        private Int32 _clockSkewInSeconds = SamlSecurityTokenHandler.DefaultClockSkewInSeconds;
        private Int32 _maximumTokenSizeInBytes = SamlSecurityTokenHandler.DefaultMaximumTokenSizeInBytes;

        /// <summary>
        /// Default for the clock skew.
        /// </summary>
        /// <remarks>300 seconds (5 minutes).</remarks>
        public const Int32 DefaultClockSkewInSeconds = 300; // 5 min.

        /// <summary>
        /// Default for the maximm token size.
        /// </summary>
        /// <remarks>2 MB (mega bytes).</remarks>
        public const Int32 DefaultMaximumTokenSizeInBytes = 1024 * 1024 * 2; // 2meg.


        /// <summary>
        /// Gets or sets the AuthenticationType when creating a <see cref="ClaimsIdentity"/> during token validation.
        /// </summary>
        /// <exception cref="ArgumentNullException"> if 'value' is null or whitespace.</exception>
        public string AuthenticationType
        {
            get
            {
                return _authenticationType;
            }
            set
            {
                if (string.IsNullOrWhiteSpace(value))
                {
                    throw new ArgumentNullException("AuthenticationType");
                }

                _authenticationType = value;
            }
        }

        /// <summary>
        /// Indicates whether the current token string can be read as a token 
        /// of the type handled by this instance.
        /// </summary>
        /// <param name="securityToken">The token string thats needs to be read.</param>
        /// <returns>'True' if the ReadToken method can parse the token string.</returns>
        public virtual bool CanReadToken(string securityToken)
        {
            if (string.IsNullOrWhiteSpace(securityToken) || securityToken.Length > MaximumTokenSizeInBytes)
            {
                return false;
            }

            using (StringReader sr = new StringReader(securityToken))
            {
                using (XmlDictionaryReader reader = XmlDictionaryReader.CreateDictionaryReader(XmlReader.Create(sr)))
                {
                    try
                    {
                        reader.MoveToContent();
                    }
                    catch(XmlException)
                    {
                        return false;
                    }

                    return base.CanReadToken(reader);
                }
            }
        }

        /// <summary>
        /// Gets and sets the maximum size in bytes, that a will be processed.
        /// </summary>
        /// <remarks>This does not set limits when reading tokens using a <see cref="XmlReader"/>. Use xml quotas on the <see cref="XmlReader"/> for those limits.</remarks>
        /// <exception cref="ArgumentOutOfRangeException">'value' less than 1.</exception>
        public Int32 ClockSkewInSeconds
        {
            get
            {
                return _clockSkewInSeconds;
            }

            set
            {
                if (value < 1)
                {
                    throw new ArgumentOutOfRangeException(string.Format(CultureInfo.InvariantCulture, ErrorMessages.IDX10100, value.ToString(CultureInfo.InvariantCulture)));
                }

                _clockSkewInSeconds = value;
            }
        }

        /// <summary>
        /// Creates claims from a Saml token.
        /// </summary>
        /// <param name="samlToken">A <see cref="SamlSecurityToken"/> that will be used to create the claims.</param>
        /// <param name="validationParameters"> contains parameters for validating the token.</param>
        /// <returns>A <see cref="ClaimsIdentity"/> containing the claims from the <see cref="SamlSecurityToken"/>.</returns>
        private ClaimsIdentity CreateClaims(SamlSecurityToken samlToken, TokenValidationParameters validationParameters)
        {
            if (samlToken == null)
            {
                throw new ArgumentNullException("samlToken");
            }

            SamlAssertion assertion = samlToken.Assertion;
            if (assertion == null)
            {
                throw new ArgumentException(ErrorMessages.IDX10202);
            }

            if (string.IsNullOrEmpty(assertion.Issuer))
            {
                throw new SecurityTokenException(ErrorMessages.IDX10203);
            }

            string issuer = ValidateIssuer(assertion.Issuer, validationParameters, samlToken);
            ClaimsIdentity identity = new ClaimsIdentity(AuthenticationType, SamlSecurityTokenRequirement.NameClaimType, SamlSecurityTokenRequirement.RoleClaimType);
            this.ProcessStatement(assertion.Statements, identity, issuer);
            return identity;
        }

        /// <summary>
        /// Gets and sets the maximum size in bytes, that a will be processed.
        /// </summary>
        /// <remarks>This does not set limits when reading tokens using a <see cref="XmlReader"/>. Use xml quotas on the <see cref="XmlReader"/> for those limits.</remarks>
        /// <exception cref="ArgumentOutOfRangeException">'value' less than 1.</exception>
        public Int32 MaximumTokenSizeInBytes
        {
            get
            {
                return _maximumTokenSizeInBytes;
            }

            set
            {
                if (value < 1)
                {
                    throw new ArgumentOutOfRangeException(string.Format(CultureInfo.InvariantCulture, ErrorMessages.IDX10101, value.ToString(CultureInfo.InvariantCulture)));
                }

                _maximumTokenSizeInBytes = value;
            }
        }

        /// <summary>
        /// Determines if an issuer is valid.
        /// </summary>
        /// <param name="issuer">the issuer to validate</param>
        /// <param name="validationParameters">parameters to define valid.</param>
        /// <param name="securityToken">the <see cref="SecurityToken"/> that is being validated.</param>
        /// <returns></returns>
        protected virtual string ValidateIssuer(string issuer, TokenValidationParameters validationParameters, SecurityToken securityToken)
        {
            return IssuerValidator.Validate(issuer, validationParameters, securityToken);
        }

        /// <summary>
        /// Validates the <see cref="SamlConditions"/> for expiration. Audience is checked seperately.
        /// </summary>
        /// <param name="conditions">SAML condition to be validated.</param>
        /// <param name="validationParameters"><see cref="TokenValidationParameters"/> contain details controling validation.</param>
        protected virtual void ValidateLifetime(SamlConditions conditions, TokenValidationParameters validationParameters)
        {
            if (conditions != null)
            {
                DateTime now = DateTime.UtcNow;
            }
        }

        /// <summary>
        /// Reads and validates a well formed <see cref="SamlSecurityToken"/>.
        /// </summary>
        /// <param name="securityToken">A string containing a well formed token.</param>
        /// <param name="validationParameters">Contains data and information needed for validation.</param>
        /// <exception cref="ArgumentNullException">'securityToken' is null or whitespace.</exception>
        /// <exception cref="ArgumentNullException">'validationParameters' is null.</exception>
        /// <exception cref="SecurityTokenException">'securityToken.Length' > <see cref="MaximumTokenSizeInBytes"/>.</exception>
        /// <returns>A <see cref="ClaimsPrincipal"/> generated from the claims in the Saml token.</returns>
        public virtual ClaimsPrincipal ValidateToken(string securityToken, TokenValidationParameters validationParameters)
        {
            if (string.IsNullOrWhiteSpace(securityToken))
            {
                throw new ArgumentNullException("securityToken");
            }

            if (validationParameters == null)
            {
                throw new ArgumentNullException("validationParameters");
            }

            if (securityToken.Length > MaximumTokenSizeInBytes)
            {
                throw new ArgumentException(string.Format(CultureInfo.InvariantCulture, ErrorMessages.IDX10209, securityToken.Length, MaximumTokenSizeInBytes));
            }

            // Calling System.IdentityModel.Tokens.SamlSecurityTokenHandler requires Configuration and IssuerTokenResolver be set.
            Configuration = new SecurityTokenHandlerConfiguration
            {
                IssuerTokenResolver = IssuerKeyRetriever.CreateIssuerTokenResolver(securityToken, validationParameters),
                MaxClockSkew = TimeSpan.FromSeconds(ClockSkewInSeconds),
            };

            SamlSecurityToken samlToken;
            using (StringReader sr = new StringReader(securityToken))
            {
                using (XmlDictionaryReader reader = XmlDictionaryReader.CreateDictionaryReader(XmlReader.Create(sr)))
                {
                    samlToken = ReadToken(reader) as SamlSecurityToken;
                }
            }

            if (samlToken.Assertion.SigningToken == null)
            {
                throw new SecurityTokenValidationException(ErrorMessages.IDX10213);
            }

            if (samlToken.Assertion == null)
            {
                throw new ArgumentException(ErrorMessages.IDX10202);
            }

            // TODO handle confirmation data and ensure exceptions are the same as jwt security token handler
            ValidateConditions(samlToken.Assertion.Conditions, false);

            if (validationParameters.ValidateAudience)
            {
                ValidateAudience(samlToken.Assertion.Conditions, validationParameters, samlToken);
            }

            ClaimsIdentity claimsIdentity = CreateClaims(samlToken, validationParameters);

            if (validationParameters.SaveSigninToken)
            {
                claimsIdentity.BootstrapContext = new BootstrapContext(securityToken);
            }

            return new ClaimsPrincipal(claimsIdentity);
        }

        /// <summary>
        /// Determines if the audience of a <see cref="SamlSecurityToken"/> is valid.
        /// </summary>
        /// <param name="conditions">the <see cref="SamlConditions"/> containing the audiences</param>
        /// <param name="validationParameters">parameters to define valid.</param>
        /// <param name="samlToken">the <see cref="SamlSecurityToken"/> that is being validated.</param>
        protected virtual void ValidateAudience(SamlConditions conditions, TokenValidationParameters validationParameters, SamlSecurityToken samlToken)
        {
            List<string> audiences = new List<string>();
            if (conditions != null)
            {
                foreach (SamlCondition condition in conditions.Conditions)
                {
                    SamlAudienceRestrictionCondition audienceRestriction = condition as SamlAudienceRestrictionCondition;
                    if (null == audienceRestriction)
                    {
                        // Skip other conditions
                        continue;
                    }

                    foreach (Uri uri in audienceRestriction.Audiences)
                    {
                        audiences.Add(uri.OriginalString);
                    }
                }
            }

            AudienceValidator.Validate(audiences, validationParameters, samlToken);
        }
    }
}