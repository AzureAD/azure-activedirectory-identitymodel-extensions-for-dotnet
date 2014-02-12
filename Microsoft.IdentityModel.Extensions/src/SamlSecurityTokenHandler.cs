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
        private TokenValidationParameters _tokenValidationParameters;

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
        protected override ClaimsIdentity CreateClaims(SamlSecurityToken samlToken)
        {
            if (_tokenValidationParameters == null)
            {
                return base.CreateClaims(samlToken);
            }

            if (samlToken == null)
            {
                throw new ArgumentNullException("samlToken");
            }

            SamlAssertion assertion = samlToken.Assertion;
            if (assertion == null)
            {
                throw new ArgumentException(ErrorMessages.IDX10202);
            }

            string issuer = ValidateIssuer(samlToken, _tokenValidationParameters);
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

            if (validationParameters.RetreiveIssuerSigningKeys != null)
            {
                foreach (SecurityKey securityKey in validationParameters.RetreiveIssuerSigningKeys(securityToken))
                {
                    yield return securityKey;
                }
            }

            if (validationParameters != null)
            {
                if (validationParameters.IssuerSigningKey != null)
                {
                    yield return validationParameters.IssuerSigningKey;
                }

                if (validationParameters.IssuerSigningKeys != null)
                {
                    foreach (SecurityKey securityKey in validationParameters.IssuerSigningKeys)
                    {
                        yield return securityKey;
                    }
                }

                if (validationParameters.IssuerSigningToken != null && validationParameters.IssuerSigningToken.SecurityKeys != null)
                {
                    X509SecurityToken x509SecurityToken = validationParameters.IssuerSigningToken as X509SecurityToken;
                    if (x509SecurityToken != null)
                    {
                        yield return new X509SecurityKey(x509SecurityToken.Certificate);
                    }
                    else
                    {
                        foreach (SecurityKey securityKey in validationParameters.IssuerSigningToken.SecurityKeys)
                        {
                            yield return securityKey;
                        }
                    }
                }

                if (validationParameters.IssuerSigningTokens != null)
                {
                    foreach (SecurityToken token in validationParameters.IssuerSigningTokens)
                    {
                        X509SecurityToken x509SecurityToken = token as X509SecurityToken;
                        if (x509SecurityToken != null)
                        {
                            yield return new X509SecurityKey(x509SecurityToken.Certificate);
                        }
                        else
                        {
                            if (token.SecurityKeys != null)
                            {
                                foreach (SecurityKey securityKey in token.SecurityKeys)
                                {
                                    yield return securityKey;
                                }
                            }
                        }
                    }
                }
            }
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
                    throw new ArgumentOutOfRangeException(string.Format(CultureInfo.InvariantCulture, ErrorMessages.IDX10100, value.ToString(CultureInfo.InvariantCulture)));
                }

                _maximumTokenSizeInBytes = value;
            }
        }

        /// <summary>
        /// Reads and validates a well fromed Saml2 token.
        /// </summary>
        /// <param name="tokenString">A Saml2 token.</param>
        /// <param name="validationParameters">Contains data and information needed to validation Saml2 token.</param>
        /// <exception cref="ArgumentNullException">'tokenString' is null.</exception>
        /// <exception cref="ArgumentNullException">'validationParameters' is null.</exception>
        /// <exception cref="SecurityTokenException">'tokenString.Length' > <see cref="MaximumTokenSizeInBytes"/>.</exception>
        /// <returns>A <see cref="ClaimsPrincipal"/> generated from the claims in the Saml2 token.</returns>
        [System.Diagnostics.CodeAnalysis.SuppressMessage("Microsoft.Naming", "CA1720")]
        [System.Diagnostics.CodeAnalysis.SuppressMessage("Microsoft.Naming", "CA2204")]
        public virtual ClaimsPrincipal ValidateToken(string tokenString, TokenValidationParameters validationParameters)
        {
            if (tokenString == null)
            {
                throw new ArgumentNullException("tokenString");
            }

            if (validationParameters == null)
            {
                throw new ArgumentNullException("validationParameters");
            }

            if (tokenString.Length > MaximumTokenSizeInBytes)
            {
                throw new SecurityTokenException(string.Format(CultureInfo.InvariantCulture, ErrorMessages.IDX10209, tokenString.Length, MaximumTokenSizeInBytes));
            }

            _tokenValidationParameters = validationParameters;

            List<SecurityToken> signingTokens = new List<SecurityToken>();
            AudienceRestriction audienceRestriction = validationParameters.ValidateAudience ? new AudienceRestriction(AudienceUriMode.Always) : new AudienceRestriction(AudienceUriMode.Never);

            // Saml spec requires all audiences to be URI's.
            if (validationParameters.ValidAudience != null && Uri.IsWellFormedUriString(validationParameters.ValidAudience, UriKind.RelativeOrAbsolute))
            {
                audienceRestriction.AllowedAudienceUris.Add(new Uri(validationParameters.ValidAudience));
            }

            if (validationParameters.ValidAudiences != null)
            {
                foreach ( string audience in validationParameters.ValidAudiences)
                {
                    if (string.IsNullOrWhiteSpace(audience))
                        continue;

                    if (Uri.IsWellFormedUriString(validationParameters.ValidAudience, UriKind.RelativeOrAbsolute))
                    {
                        audienceRestriction.AllowedAudienceUris.Add(new Uri(audience));
                    }
                }
            }

            List<SecurityKey> namedKeys = new List<SecurityKey>();
            foreach (SecurityKey securityKey in RetreiveIssuerSigningKeys(tokenString, validationParameters))
            {
                X509SecurityKey x509SecurityKey = securityKey as X509SecurityKey;
                if (x509SecurityKey != null)
                {
                    signingTokens.Add(new X509SecurityToken(x509SecurityKey.Certificate));
                }
                else
                {
                    X509AsymmetricSecurityKey x509AsymmetricSecurityKey = securityKey as X509AsymmetricSecurityKey;
                    if (x509AsymmetricSecurityKey != null)
                    {

                    }
                    else
                    {
                        namedKeys.Add(securityKey);
                    }
                }
            }

            if (namedKeys.Count > 0)
            {
                signingTokens.Add(new NamedKeySecurityToken("unknown", namedKeys));
            }

            // TODO: brent, post preview - ServiceTokenResolver needs to be set for encrypted tokens.
            Configuration = new SecurityTokenHandlerConfiguration
            {
                AudienceRestriction = audienceRestriction,
                SaveBootstrapContext = validationParameters.SaveSigninToken,
                IssuerTokenResolver = SecurityTokenResolver.CreateDefaultSecurityTokenResolver(signingTokens.AsReadOnly(), true),
                //TODO - why doesn't SAML2 need this?
                CertificateValidator = X509CertificateValidator.None,
            };

            SamlSecurityToken samlToken;
            using (StringReader sr = new StringReader(tokenString))
            {
                using (XmlDictionaryReader reader = XmlDictionaryReader.CreateDictionaryReader(XmlReader.Create(sr)))
                {
                    samlToken = ReadToken(reader) as SamlSecurityToken;
                }
            }

            ReadOnlyCollection<ClaimsIdentity> identities = ValidateToken(samlToken);
            return new ClaimsPrincipal(identities);
        }

        protected virtual string ValidateIssuer(SecurityToken securityToken, TokenValidationParameters validationParameters)
        {
            if (securityToken == null)
            {
                throw new ArgumentNullException("securityToken");
            }

            if (validationParameters == null)
            {
                throw new ArgumentNullException("validationParameters");
            }

            SamlSecurityToken samlToken = securityToken as SamlSecurityToken;
            if (samlToken == null)
            {
                throw new ArgumentException(string.Format(CultureInfo.InvariantCulture, ErrorMessages.IDX10206, typeof(SamlSecurityToken).ToString(), typeof(SecurityToken)));
            }

            SamlAssertion assertion = samlToken.Assertion;
            if (assertion == null)
            {
                throw new ArgumentException(ErrorMessages.IDX10202);
            }

            string issuer = assertion.Issuer;
            if (string.IsNullOrEmpty(issuer))
            {
                throw new SecurityTokenException(ErrorMessages.IDX10203);
            }

            if (!validationParameters.ValidateIssuer)
            {
                return issuer;
            }

            if (validationParameters.IssuerValidator != null)
            {
                if (validationParameters.IssuerValidator(issuer, samlToken))
                {
                    return issuer;
                }
            }

            // Throw if all possible places to validate against are null or empty
            if (string.IsNullOrWhiteSpace(validationParameters.ValidIssuer) && (validationParameters.ValidIssuers == null))
            {
                throw new ArgumentException(string.Format(CultureInfo.InvariantCulture, ErrorMessages.IDX10204));
            }

            if (!string.IsNullOrWhiteSpace(validationParameters.ValidIssuer) && string.Equals(validationParameters.ValidIssuer, issuer, StringComparison.Ordinal))
            {
                return issuer;
            }

            if (null != validationParameters.ValidIssuers)
            {
                foreach (string str in validationParameters.ValidIssuers)
                {
                    if (string.Equals(str, issuer, StringComparison.Ordinal))
                    {
                        return issuer;
                    }
                }
            }

            string validIssuer = validationParameters.ValidIssuer ?? "null";
            string validIssuers = "null";
            if (validationParameters.ValidIssuers != null)
            {
                bool first = true;
                foreach( string str in validationParameters.ValidIssuers)
                {
                    if (!string.IsNullOrWhiteSpace(str))
                    {
                        validIssuers += str;
                        if (!first)
                        {
                            validIssuers += ", ";
                        }
                        first = false;
                    }
                }
            }

            throw new SecurityTokenValidationException(string.Format(CultureInfo.InvariantCulture, ErrorMessages.IDX10205, validIssuer, validIssuers, issuer));
        }
    }
}