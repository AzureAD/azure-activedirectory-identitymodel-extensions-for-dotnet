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
        private Int32 _clockSkewInSeconds = Saml2SecurityTokenHandler.DefaultClockSkewInSeconds;
        private Int32 _maximumTokenSizeInBytes = Saml2SecurityTokenHandler.DefaultMaximumTokenSizeInBytes;

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
        /// Creates claims from a Saml token.
        /// </summary>
        /// <param name="samlToken">The SamlSecurityToken.</param>
        /// <returns>A <see cref="ClaimIdentity"/> containing the claims from the <see cref="SamlSecurityToken"/>.</returns>
        protected virtual ClaimsIdentity CreateClaims(SamlSecurityToken samlToken, TokenValidationParameters validationParameters)
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
        /// Produces a <see cref="IEnumerable{SecurityKey}"/> to use when validating the signature of the jwt.
        /// </summary>
        /// <param name="securityToken">A security token that needs to have its signture validated.</param>
        /// <param name="validationParameters">A <see cref="TokenValidationParameters"/> instance that has references to multiple <see cref="SecurityKey"/>.</param>
        /// <returns>Returns a <see cref="IEnumerable{SecurityKey}"/> of the keys to use for signature validation.</returns>
        /// <exception cref="ArgumentNullException">'validationParameters' is null.</exception>
        public virtual IEnumerable<SecurityKey> RetreiveIssuerSigningKeys(string securityToken, TokenValidationParameters validationParameters)
        {
            return IssuerKeyRetriever.RetreiveIssuerSigningKeys(securityToken, validationParameters);
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

        public virtual string ValidateIssuer(string issuer, TokenValidationParameters validationParameters, SecurityToken securityToken)
        {
            return IssuerValidator.Validate(issuer, validationParameters, securityToken);
        }

        /// <summary>
        /// Reads and validates a well formed Saml2 token.
        /// </summary>
        /// <param name="securityToken">A Saml2 token.</param>
        /// <param name="validationParameters">Contains data and information needed to validation Saml2 token.</param>
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