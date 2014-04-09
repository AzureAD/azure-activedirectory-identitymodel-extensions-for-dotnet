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
    public class Saml2SecurityTokenHandler : System.IdentityModel.Tokens.Saml2SecurityTokenHandler, ISecurityTokenValidator
    {
        private string _authenticationType = AuthenticationTypes.Federation;
        private Int32 _clockSkewInSeconds = Saml2SecurityTokenHandler.DefaultClockSkewInSeconds;
        private Int32 _maximumTokenSizeInBytes = Saml2SecurityTokenHandler.DefaultMaximumTokenSizeInBytes;

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
        /// Determines if the string is a well formed Saml2 token (see http://docs.oasis-open.org/security/saml/Post2.0/saml-session-token/v1.0/csd01/saml-session-token-v1.0-csd01.html)
        /// </summary>
        /// <param name="securityToken">string that should represent a valid Saml2 Token.</param>
        /// <returns>
        /// <para>'true' if the string starts with an xml element that conforms to the spec above.</para>
        /// <para>'false' if token.Length * 2 >  <see cref="MaximumTokenSizeInBytes"/>.</para>
        /// </returns>
        /// <exception cref="ArgumentNullException">'securityToken' is null.</exception>
        public override bool CanReadToken(string securityToken)
        {
            if (securityToken == null)
            {
                throw new ArgumentNullException("securityToken");
            }

            if (securityToken.Length > MaximumTokenSizeInBytes )
            {
                return false;
            }

            using (StringReader sr = new StringReader(securityToken))
            {
                using (XmlDictionaryReader reader = XmlDictionaryReader.CreateDictionaryReader(XmlReader.Create(sr)))
                {
                    reader.MoveToContent();
                    return CanReadToken(reader);
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
        /// Creates claims from a Saml2 token.
        /// </summary>
        /// <param name="samlToken">The Saml2SecurityToken.</param>
        /// <param name="validationParameters"> contains parameters for validating the token.</param>
        /// <returns>An IClaimIdentity.</returns>
        protected virtual ClaimsIdentity CreateClaims(Saml2SecurityToken samlToken, TokenValidationParameters validationParameters)
        {
            if (samlToken == null)
            {
                throw new ArgumentNullException("samlToken");
            }

            Saml2Assertion assertion = samlToken.Assertion;
            if (assertion == null)
            {
                throw new ArgumentException(ErrorMessages.IDX10202);
            }

            if (assertion.Issuer == null)
            {
                throw new ArgumentException(ErrorMessages.IDX10210);
            }            

            string issuer = assertion.Issuer.Value;
            if (string.IsNullOrEmpty(issuer))
            {
                throw new SecurityTokenException(ErrorMessages.IDX10203);
            }

            issuer = ValidateIssuer(issuer, validationParameters, samlToken);
            ClaimsIdentity identity = new ClaimsIdentity(AuthenticationType, SamlSecurityTokenRequirement.NameClaimType, SamlSecurityTokenRequirement.RoleClaimType);
            this.ProcessSamlSubject(assertion.Subject, identity, issuer);
            this.ProcessStatement(assertion.Statements, identity, issuer);
            return identity;
        }

        /// <summary>
        /// Produces a <see cref="IEnumerable{SecurityKey}"/> to use when validating the signature of the jwt.
        /// </summary>
        /// <param name="securityToken">A security token that needs to have its signture validated.</param>
        /// <param name="validationParameters">A <see cref="TokenValidationParameters"/> instance that has references to multiple <see cref="SecurityKey"/>.</param>
        /// <returns>Returns a <see cref="IEnumerable{SecurityKey}"/> of the keys to use for signature validation.</returns>
        /// <exception cref="ArgumentNullException">'validationParameters' is null.</exception>
        public virtual IEnumerable<SecurityKey> RetrieveIssuerSigningKeys(string securityToken, TokenValidationParameters validationParameters)
        {
            return IssuerKeyRetriever.RetrieveIssuerSigningKeys(securityToken, validationParameters);
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
        /// Reads and validates a well fromed Saml2 token.
        /// </summary>
        /// <param name="securityToken">A Saml2 token.</param>
        /// <param name="validationParameters">Contains data and information needed for validation.</param>
        /// <exception cref="ArgumentNullException">'securityToken' is null.</exception>
        /// <exception cref="ArgumentNullException">'validationParameters' is null.</exception>
        /// <exception cref="SecurityTokenException">'securityToken.Length' > <see cref="MaximumTokenSizeInBytes"/>.</exception>
        /// <returns>A <see cref="ClaimsPrincipal"/> generated from the claims in the Saml2 token.</returns>
        [System.Diagnostics.CodeAnalysis.SuppressMessage("Microsoft.Naming", "CA1720")]
        [System.Diagnostics.CodeAnalysis.SuppressMessage("Microsoft.Naming", "CA2204")]
        public virtual ClaimsPrincipal ValidateToken(string securityToken, TokenValidationParameters validationParameters)
        {
            if (securityToken == null)
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

            Configuration = new SecurityTokenHandlerConfiguration
            {
                IssuerTokenResolver = IssuerKeyRetriever.CreateIssuerTokenResolver(securityToken, validationParameters),
                MaxClockSkew = TimeSpan.FromSeconds(ClockSkewInSeconds),
            };

            Saml2SecurityToken samlToken;
            using (StringReader sr = new StringReader(securityToken))
            {
                using (XmlDictionaryReader reader = XmlDictionaryReader.CreateDictionaryReader(XmlReader.Create(sr)))
                {
                    samlToken = ReadToken(reader) as Saml2SecurityToken;
                }
            }

            if (samlToken.IssuerToken == null)
            {
                throw new SecurityTokenValidationException(ErrorMessages.IDX10213);
            }

            if (samlToken.Assertion == null)
            {
                throw new ArgumentException(ErrorMessages.IDX10202);
            }

            ValidateConditions(samlToken.Assertion.Conditions, validationParameters);

            Saml2SubjectConfirmation subjectConfirmation = samlToken.Assertion.Subject.SubjectConfirmations[0];
            if (subjectConfirmation.SubjectConfirmationData != null)
            {
                // TODO handle confirmation data and ensure exceptions are the same as jwt security token handler
                ValidateConfirmationData(subjectConfirmation.SubjectConfirmationData);
            }

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
        /// Determines if the audience of a <see cref="Saml2SecurityToken"/> is valid.
        /// </summary>
        /// <param name="conditions">the <see cref="Saml2Conditions"/> containing the audiences</param>
        /// <param name="validationParameters">parameters to define valid.</param>
        /// <param name="samlToken">the <see cref="Saml2SecurityToken"/> that is being validated.</param>
        protected virtual void ValidateAudience(Saml2Conditions conditions, TokenValidationParameters validationParameters, Saml2SecurityToken samlToken)
        {
            List<string> audiences = new List<string>();
            if (conditions != null)
            {
                foreach (Saml2AudienceRestriction restriction in conditions.AudienceRestrictions)
                {
                    foreach (Uri uri in restriction.Audiences)
                    {
                        audiences.Add(uri.OriginalString);
                    }
                }
            }

            AudienceValidator.Validate(audiences, validationParameters, samlToken);
        }

        /// <summary>
        /// Validates the <see cref="Saml2Conditions"/> for expiration. Audience is checked seperately.
        /// </summary>
        /// <param name="conditions">SAML 2.0 condition to be validated.</param>
        /// <param name="validationParameters"><see cref="TokenValidationParameters"/> contain details controling validation.</param>
        protected virtual void ValidateConditions(Saml2Conditions conditions, TokenValidationParameters validationParameters)
        {
            if (conditions != null)
            {
                DateTime now = DateTime.UtcNow;

                if (conditions.NotBefore != null && conditions.NotBefore.HasValue
                    && DateTimeUtil.Add(now, TimeSpan.FromSeconds(ClockSkewInSeconds)) < conditions.NotBefore.Value.ToUniversalTime())
                {
                    throw new SecurityTokenInvalidLifetimeException(string.Format(CultureInfo.InvariantCulture, ErrorMessages.IDX10216, now, ClockSkewInSeconds, conditions.NotBefore.Value));
                }

                if (conditions.NotOnOrAfter != null && conditions.NotOnOrAfter.HasValue
                    && DateTimeUtil.Add(now, TimeSpan.FromSeconds(ClockSkewInSeconds).Negate()) >= conditions.NotOnOrAfter.Value)
                {
                    throw new SecurityTokenInvalidLifetimeException(string.Format(CultureInfo.InvariantCulture, ErrorMessages.IDX10217, now, ClockSkewInSeconds, conditions.NotBefore.Value));
                }

                if (conditions.OneTimeUse)
                {
                    throw new SecurityTokenValidationException(ErrorMessages.IDX10217);
                }

                if (conditions.ProxyRestriction != null)
                {
                    throw new SecurityTokenValidationException(ErrorMessages.IDX10218);
                }
            }
        }

        /// <summary>
        /// Determines if an issuer is valid.
        /// </summary>
        /// <param name="issuer">the issuer to validate</param>
        /// <param name="validationParameters">parameters to define valid.</param>
        /// <param name="securityToken">the <see cref="SecurityToken"/> that is being validated.</param>
        /// <returns></returns>
        public virtual string ValidateIssuer(string issuer, TokenValidationParameters validationParameters, SecurityToken securityToken)
        {
            return IssuerValidator.Validate(issuer, validationParameters, securityToken);
        }

    }
}