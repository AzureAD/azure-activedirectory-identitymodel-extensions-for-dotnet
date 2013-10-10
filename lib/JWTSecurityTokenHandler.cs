//------------------------------------------------------------------------------
// Copyright (c) Microsoft Corporation.  All rights reserved.
//------------------------------------------------------------------------------

using System.Collections.Generic;
using System.Collections.ObjectModel;
using System.ComponentModel;
using System.Configuration;
using System.Globalization;
using System.IdentityModel.Protocols.WSTrust;
using System.IdentityModel.Selectors;
using System.Runtime.Serialization;
using System.Security.Claims;
using System.Text;
using System.Text.RegularExpressions;
using System.Xml;
using Elements = System.IdentityModel.Tokens.JwtConfigurationStrings.Elements;

namespace System.IdentityModel.Tokens
{    
    /// <summary>
    /// A <see cref="SecurityTokenHandler"/> designed for creating and validating Json Web Tokens. See http://tools.ietf.org/html/draft-ietf-oauth-json-web-token-07.
    /// </summary>
    public class JwtSecurityTokenHandler : SecurityTokenHandler
    {
        private static IDictionary<string, string> _outboundAlgorithmMap =  new Dictionary<string, string>() 
                                                                            { 
                                                                                { SecurityAlgorithms.RsaSha256Signature, JwtConstants.Algorithms.RSA_SHA256 }, 
                                                                                { SecurityAlgorithms.HmacSha256Signature, JwtConstants.Algorithms.HMAC_SHA256 },
                                                                            };

        private static IDictionary<string, string> _inboundAlgorithmMap =   new Dictionary<string, string>() 
                                                                            { 
                                                                                { JwtConstants.Algorithms.RSA_SHA256, SecurityAlgorithms.RsaSha256Signature }, 
                                                                                { JwtConstants.Algorithms.HMAC_SHA256,SecurityAlgorithms.HmacSha256Signature },
                                                                            };

        private static IDictionary<string, string> _inboundClaimTypeMap  = ClaimTypeMapping.InboundClaimTypeMap;
        private static IDictionary<string, string> _outboundClaimTypeMap = ClaimTypeMapping.OutboundClaimTypeMap;
        private static string _shortClaimTypeProperty = ClaimProperties.Namespace + "/ShortTypeName";

        private SignatureProviderFactory _signatureProviderFactory       = new SignatureProviderFactory();
        private JwtSecurityTokenRequirement _jwtSecurityTokenRequirement = new JwtSecurityTokenRequirement();

        // the Sts pipeline expects the first identifier to be a string that 
        // Uri.TryCreate( tokenIdentifiers[0], UriKind.Absolute, out result ) will be true.
        // if that is not true, sts's using our sts class will start failing.
        private static string[] _tokenTypeIdentifiers = new string[] { JwtConstants.TokenTypeAlt, JwtConstants.TokenType };
        
        // Token format: 'header.payload.signature'. Signature is optional, but '.' is required.
        internal const string JsonCompactSerializationRegex = @"^[A-Za-z0-9-_]+\.[A-Za-z0-9-_]+\.[A-Za-z0-9-_]*$";

        /// <summary>
        /// Initializes an instance of <see cref="JwtSecurityTokenHandler"/>
        /// </summary>
        public JwtSecurityTokenHandler()
        {
            RequireSignedTokens = true;
            RequireExpirationTime = true;
        }

        /// <summary>Gets or sets the <see cref="IDictionary{TKey, TValue}"/> used to map Inbound Cryptographic Algorithms.</summary>
        /// <remarks>Strings that describe Cryptographic Algorithms that are understood by the runtime are not necessarily the same values used in the JsonWebToken specification.
        /// <para>When a <see cref="JwtSecurityToken"/> signature is validated, the algorithm is obtained from the HeaderParameter { alg, 'value' }.  
        /// The 'value' is translated according to this mapping and the translated 'value' is used when performing cryptographic operations.</para>
        /// <para>Default mapping is:</para>
        /// <para>&#160;&#160;&#160;&#160;RS256 => http://www.w3.org/2001/04/xmldsig-more#rsa-sha256 </para>
        /// <para>&#160;&#160;&#160;&#160;HS256 => http://www.w3.org/2001/04/xmldsig-more#hmac-sha256 </para>
        /// </remarks>
        /// <exception cref="ArgumentNullException">'value' is null.</exception>
        public static IDictionary<string, string> InboundAlgorithmMap
        {
            get
            {
                return _inboundAlgorithmMap;
            }

            set
            {
                if ( value == null )
                {
                    throw new ArgumentNullException( "value" );
                }

                _outboundAlgorithmMap = value;
            }
        }

        /// <summary>Gets or sets the <see cref="IDictionary{TKey, TValue}"/> used to map Outbound Cryptographic Algorithms.</summary>
        /// <remarks>Strings that describe Cryptographic Algorithms understood by the runtime are not necessarily the same in the JsonWebToken specification.
        /// <para>This property contains mappings the will be used to when creating a <see cref="JwtHeader"/> and setting the HeaderParameter { alg, 'value' }. 
        /// The 'value' set is translated according to this mapping.
        /// </para>
        /// <para>Default mapping is:</para>
        /// <para>&#160;&#160;&#160;&#160;http://www.w3.org/2001/04/xmldsig-more#rsa-sha256  => RS256</para>
        /// <para>&#160;&#160;&#160;&#160;http://www.w3.org/2001/04/xmldsig-more#hmac-sha256 => HS256</para>
        /// </remarks>
        /// <exception cref="ArgumentNullException">'value' is null.</exception>
        public static IDictionary<string, string> OutboundAlgorithmMap
        {
            get
            {
                return _outboundAlgorithmMap;
            }

            set
            {
                if ( value == null )
                {
                    throw new ArgumentNullException( "value" );
                }

                _outboundAlgorithmMap = value;
            }
        }

        /// <summary>
        /// Gets or sets the <see cref="InboundClaimTypeMap"/> that is used when setting the <see cref="Claim.Type"/> for claims in the <see cref="ClaimsPrincipal"/> extracted when validating a <see cref="JwtSecurityToken"/>. 
        /// <para>The <see cref="Claim.Type"/> is set to the JSON claim 'name' after translating using this mapping.</para>
        /// </summary>
        /// <exception cref="ArgumentNullException">'value is null.</exception>
        public static IDictionary<string, string> InboundClaimTypeMap
        {
            get
            {
                return _inboundClaimTypeMap;
            }

            set
            {
                if ( value == null )
                {
                    throw new ArgumentNullException( "value" );
                }

                _inboundClaimTypeMap = value;
            }
        }

        /// <summary>
        /// <para>Gets or sets the <see cref="OutboundClaimTypeMap"/> that is used when creating a <see cref="JwtSecurityToken"/> from <see cref="Claim"/>(s).</para>
        /// <para>The JSON claim 'name' value is set to <see cref="Claim.Type"/> after translating using this mapping.</para>
        /// </summary>
        /// <remarks>This mapping is applied only when using <see cref="JwtPayload.AddClaim"/> or <see cref="JwtPayload.AddClaims"/>. Adding values directly will not result in translation.</remarks>
        /// <exception cref="ArgumentNullException">'value is null.</exception>
        public static IDictionary<string, string> OutboundClaimTypeMap
        {
            get
            {
                return _outboundClaimTypeMap;
            }

            set
            {
                if ( value == null )
                {
                    throw new ArgumentNullException( "value" );
                }

                _outboundClaimTypeMap = value;
            }
        }

        /// <summary>
        /// Gets or sets the property name of <see cref="Claim.Properties"/> the will contain the original JSON claim 'name' if a mapping occurred when the <see cref="Claim"/>(s) were created.
        /// <para>See <seealso cref="InboundClaimTypeMap"/> for more information.</para>
        /// </summary>
        /// <exception cref="ArgumentException">if <see cref="string"/>.IsIsNullOrWhiteSpace('value') is true.</exception>
        public static string ShortClaimTypeProperty
        {
            get
            {
                return _shortClaimTypeProperty;
            }

            set
            {
                if ( string.IsNullOrWhiteSpace( value ) )
                {
                    throw new ArgumentException( string.Format( CultureInfo.InvariantCulture, JwtErrors.Jwt10000, "value" ) );
                }

                _shortClaimTypeProperty = value;
            }
        }
            
        /// <summary>
        /// Determines if the <see cref="XmlReader"/> is positioned on a well formed &lt;BinarySecurityToken> element.
        /// </summary>
        /// <param name="reader"><see cref="XmlReader"/> positioned at xml.</param>
        /// <returns>
        /// <para>'true' if the reader is positioned at an element &lt;BinarySecurityToken>.
        /// in the namespace: 'http://docs.oasis-open.org/wss/2004/01/oasis-200401-wss-wssecurity-secext-1.0.xsd'</para>
        /// <para>With an attribute of 'valueType' equal to one of: </para>
        /// <para>&#160;&#160;&#160;&#160;"urn:ietf:params:oauth:token-type:jwt", "JWT" </para>
        /// <para>
        /// For example: &lt;wsse:BinarySecurityToken valueType = "JWT"> ...
        /// </para>
        /// 'false' otherwise.
        /// </returns>
        /// <remarks>The 'EncodingType' attribute is optional, if it is set, it must be equal to: "http://docs.oasis-open.org/wss/2004/01/oasis-200401-wss-soap-message-security-1.0#Base64Binary".</remarks>
        /// <exception cref="ArgumentNullException">'reader' is null.</exception>
        public override bool CanReadToken( XmlReader reader )
        {
            if ( reader == null )
            {
                throw new ArgumentNullException( "reader" );
            }

            reader.MoveToContent();

            if ( reader.IsStartElement( WSSecurity10Constants.Elements.BinarySecurityToken, WSSecurity10Constants.Namespace ) )
            {
                string valueType     = reader.GetAttribute( WSSecurity10Constants.Attributes.ValueType, null );
                string encodingType  = reader.GetAttribute( WSSecurity10Constants.Attributes.EncodingType, null );

                if ( encodingType != null && !StringComparer.Ordinal.Equals( encodingType, WSSecurity10Constants.Base64EncodingType ) )
                {
                    return false;
                }

                if ( valueType != null && StringComparer.Ordinal.Equals( valueType, JwtConstants.TokenTypeAlt ) )
                {
                    return true;
                }

                if ( valueType != null && StringComparer.OrdinalIgnoreCase.Equals( valueType, JwtConstants.TokenType ) )
                {
                    return true;
                }
            }

            return false;
        }

        /// <summary>
        /// Determines if the string is a well formed Json Web token (see http://tools.ietf.org/html/draft-ietf-oauth-json-web-token-07)
        /// </summary>
        /// <remarks>Uses <see cref="Regex.IsMatch(string, string)"/>( token, @"^[A-Za-z0-9-_]+\.[A-Za-z0-9-_]+\.[A-Za-z0-9-_]*$" ).
        /// </remarks>
        /// <returns>
        /// <para>'true' if the token is in JSON compact serialization format.</para>
        /// <para>'false' if token.Length * 2 >  <see cref="MaxTokenSizeInBytes"/>.</para>
        /// </returns>
        /// <exception cref="ArgumentNullException">'token' is null.</exception>
        public override bool CanReadToken( string token )
        {
            if ( token == null )
            {
                throw new ArgumentNullException( "token" );
            }

            if ( token.Length * 2 > MaxTokenSizeInBytes )
            {
                return false;
            }

            return Regex.IsMatch( token, JsonCompactSerializationRegex );
        }

        /// <summary>
        /// Returns 'true' which indicates this instance can validate a <see cref="JwtSecurityToken"/>.
        /// </summary>
        public override bool CanValidateToken
        {
            get { return true; }
        }

        /// <summary>
        /// Returns 'true', which indicates this instance can write <see cref="JwtSecurityToken"/>.
        /// </summary>
        public override bool CanWriteToken
        {
            get { return true; }
        }

        /// <summary>
        /// Gets or sets the <see cref="X509CertificateValidator"/> responsible for validating the certificate that signed the <see cref="JwtSecurityToken"/>.
        /// </summary>
        /// <remarks>The <see cref="X509CertificateValidator"/> returned using the following search path:
        /// <para>
        /// 1. <seealso cref="System.IdentityModel.Tokens.JwtSecurityTokenRequirement.CertificateValidator"/> if not null, return this value.
        /// </para>
        /// ----
        /// <para>
        /// 2. <see cref="JwtSecurityTokenHandler"/>.Configuration.CertificateValidator if not null, return this value.
        /// </para>
        /// ----
        /// <para>
        /// 3. <see cref="SecurityTokenHandlerConfiguration.DefaultCertificateValidator"/>.
        /// </para>
        /// </remarks>
        public X509CertificateValidator CertificateValidator
        {
            get
            {
                if ( JwtSecurityTokenRequirement.CertificateValidator == null )
                {
                    if ( Configuration != null )
                    {
                        return Configuration.CertificateValidator;
                    }
                    else
                    {
                        return SecurityTokenHandlerConfiguration.DefaultCertificateValidator;
                    }
                }
                else
                {
                    return JwtSecurityTokenRequirement.CertificateValidator;
                }
            }

            set
            {
                JwtSecurityTokenRequirement.CertificateValidator = value;
            }
        }

        /// <summary>
        /// Gets or sets the default token lifetime.
        /// </summary>
        /// <remarks>
        /// <para>This value is used when creating a <see cref="JwtSecurityToken"/> and the <see cref="Lifetime"/> is not specified.</para>
        /// If <see cref="JwtSecurityTokenHandler.RequireExpirationTime"/> is true, then
        /// an expiration claim { exp, 'value' } will added to the <see cref="JwtPayload"/>. 'value' = <see cref="DateTime.UtcNow"/> + <see cref="TimeSpan.FromMinutes"/>( <see cref="DefaultTokenLifetimeInMinutes"/> ).
        /// <para>If only <see cref="Lifetime.Created"/> is specified, expiration will add to that value.</para>
        /// <para>Default is 600 (minutes).</para></remarks>
        /// <exception cref="ArgumentOutOfRangeException">'value' == 0.</exception>
        public UInt32 DefaultTokenLifetimeInMinutes
        {
            get
            {
                return JwtSecurityTokenRequirement.DefaultTokenLifetimeInMinutes;
            }

            set
            {
                if ( value == 0 )
                {
                    throw new ArgumentOutOfRangeException( "value", JwtErrors.Jwt10115 );
                }

                JwtSecurityTokenRequirement.DefaultTokenLifetimeInMinutes = value;
            }
        }

        /// <summary>
        /// Gets or sets the <see cref="JwtSecurityTokenRequirement"/>.
        /// </summary>
        /// <remarks>These settings have precedence over <see cref="SecurityTokenHandlerConfiguration"/>.</remarks>
        /// <exception cref="ArgumentNullException">'value' is null.</exception>
        public JwtSecurityTokenRequirement JwtSecurityTokenRequirement
        {
            get
            {
                return _jwtSecurityTokenRequirement;
            }

            set
            {
                if ( value == null )
                {
                    throw new ArgumentNullException( "value" );
                }

                _jwtSecurityTokenRequirement = value;
            }
        }

        /// <summary>
        /// Gets or sets the <see cref="string"/> passed to <see cref="ClaimsIdentity(string, string, string)"/>. 
        /// </summary>
        /// <remarks>
        /// Controls the value <see cref="ClaimsIdentity.Name"/> property will return. It will return the first <see cref="Claim.Value"/> where the <see cref="Claim.Type"/> equals <see cref="NameClaimType"/>.
        /// </remarks>
        public string NameClaimType
        {
            get
            {
                if ( JwtSecurityTokenRequirement.NameClaimType != null )
                {
                    return JwtSecurityTokenRequirement.NameClaimType;
                }

                return ClaimsIdentity.DefaultNameClaimType;
            }

            set
            {
                JwtSecurityTokenRequirement.NameClaimType = value;
            }
        }

        /// <summary>
        /// Gets or sets the clockskew to use when validating times.
        /// </summary>
        /// <remarks>The following search path is used to obtain the clockskew to return:
        /// <para>
        /// 1. If <see cref="JwtSecurityTokenHandler.JwtSecurityTokenRequirement"/>.MaxClockSkew.HasValue, return this value.
        /// </para>
        /// ----
        /// <para>
        /// 2. If <see cref="JwtSecurityTokenHandler"/>.Configuration is not null, return <see cref="JwtSecurityTokenHandler"/>.Configuration.MaxClockSkew.
        /// </para>
        /// ----
        /// <para>
        /// 3. default: <see cref="SecurityTokenHandlerConfiguration.DefaultMaxClockSkew"/>.
        /// </para>
        /// </remarks>
        /// <exception cref="ArgumentOutOfRangeException">'value' is less than <see cref="TimeSpan.Zero"/></exception>
        public TimeSpan MaxClockSkew
        {
            get
            {
                if ( JwtSecurityTokenRequirement.MaxClockSkew.HasValue )
                {
                    return JwtSecurityTokenRequirement.MaxClockSkew.Value;
                }
                else if ( Configuration != null )
                {
                    return Configuration.MaxClockSkew;
                }
                else
                {
                    return SecurityTokenHandlerConfiguration.DefaultMaxClockSkew;
                }
            }

            set
            {
                if ( value < TimeSpan.Zero )
                {
                    throw new ArgumentOutOfRangeException( string.Format( CultureInfo.InvariantCulture, JwtErrors.Jwt10111, value ) );
                }

                JwtSecurityTokenRequirement.MaxClockSkew = value;
            }
        }

        /// <summary>
        /// Gets or sets the size limit when reading a token as a string.
        /// </summary>
        /// <remarks>This does not set limits when reading tokens using a <see cref="XmlReader"/>. Use xml quotas on the <see cref="XmlReader"/> for those limits.</remarks>
        /// <exception cref="ArgumentOutOfRangeException">'value' == 0.</exception>
        public UInt32 MaxTokenSizeInBytes
        {
            get
            {
                return JwtSecurityTokenRequirement.MaximumTokenSizeInBytes;
            }

            set
            {
                if ( value == 0 )
                {
                    throw new ArgumentOutOfRangeException( string.Format( CultureInfo.InvariantCulture, JwtErrors.Jwt10323, value ) );
                }

                JwtSecurityTokenRequirement.MaximumTokenSizeInBytes = value;
            }
        }

        /// <summary>
        /// Gets or sets a value indicating whether if the 'expiration' value in a <see cref="JwtSecurityToken"/> is required.
        /// </summary>
        /// <remarks>If 'true' then:
        /// <para>A <see cref="JwtSecurityToken"/> will be considered invalid if it does not contain an 'expiration' value.</para>
        /// <para>When creating a <see cref="JwtSecurityToken"/> if <see cref="Lifetime"/> is not specified a default will be added to the payload. See <seealso cref="DefaultTokenLifetimeInMinutes"/> for details on the calculation of the 'expiration' value.</para></remarks>
        [DefaultValue( true )]
        public bool RequireExpirationTime { get; set; }

        /// <summary>
        /// Gets or sets a value indicating whether a <see cref="JwtSecurityToken"/> can be valid if not signed.
        /// </summary>
        /// <remarks>If true then:
        /// <para>A <see cref="JwtSecurityToken"/> will be considered invalid if it does not contain a 'signature'.</para>
        /// </remarks>
        [DefaultValue( true )]
        public bool RequireSignedTokens { get; set; }

        /// <summary>
        /// Gets or sets the <see cref="string"/> passed to <see cref="ClaimsIdentity(string, string, string)"/>.
        /// </summary>
        /// <remarks>
        /// <para>Controls the <see cref="Claim"/>(s) returned from <see cref="ClaimsPrincipal.IsInRole( string )"/>.</para>
        /// <para>Each <see cref="Claim"/> returned will have a <see cref="Claim.Type"/> equal to <see cref="RoleClaimType"/>.</para>
        /// </remarks>
        public string RoleClaimType
        {
            get
            {
                if ( JwtSecurityTokenRequirement.RoleClaimType != null )
                {
                    return JwtSecurityTokenRequirement.RoleClaimType;
                }

                return ClaimsIdentity.DefaultRoleClaimType;
            }

            set
            {
                JwtSecurityTokenRequirement.RoleClaimType = value;
            }
        }

        /// <summary>
        /// Gets or sets the <see cref="SignatureProviderFactory"/> for creating <see cref="SignatureProvider"/>(s).
        /// </summary>
        /// <remarks>This extensibility point can be used to insert custom <see cref="SignatureProvider"/>(s).
        /// <para><see cref="System.IdentityModel.Tokens.SignatureProviderFactory.CreateForVerifying(SecurityKey, string)"/> is called to obtain a <see cref="SignatureProvider"/>(s) when needed.</para></remarks>
        /// <exception cref="ArgumentNullException">'value' is null.</exception>
        public SignatureProviderFactory SignatureProviderFactory
        {
            get 
            { 
                return _signatureProviderFactory; 
            }

            set
            {
                if ( value == null )
                {
                    throw new ArgumentNullException( "value" );
                }

                _signatureProviderFactory = value;
            }
        }

        /// <summary>
        /// Gets the <see cref="Type"/> supported by this handler.
        /// </summary>
        public override Type TokenType
        {
            get { return typeof( JwtSecurityToken ); }
        }

        /// <summary>
        /// Creates <see cref="SecurityKeyIdentifierClause"/> that identifies the <see cref="SecurityToken"/>.
        /// </summary>
        /// <returns>Always returns null</returns>
        /// <remarks>Called by the mainline scenarios which would result in the base class throwing a <see cref="NotImplementedException"/>.
        /// If the <see cref="SecurityKeyIdentifierClause"/> is required override this method.</remarks>
        public override SecurityKeyIdentifierClause CreateSecurityTokenReference( SecurityToken token, bool attached )
        {
            return null;
        }

        /// <summary>
        /// Creates a <see cref="JwtSecurityToken"/> based on values found in the <see cref="SecurityTokenDescriptor"/>.
        /// </summary>
        /// <param name="tokenDescriptor">Contains the parameters used to create the token.</param>
        /// <returns>A <see cref="JwtSecurityToken"/>.</returns>
        /// <remarks>
        /// If <see cref="SecurityTokenDescriptor.SigningCredentials"/> is not null, <see cref="JwtSecurityToken.RawData"/> will be signed.
        /// </remarks>
        /// <exception cref="ArgumentNullException">'tokenDescriptor' is null.</exception>
        public override SecurityToken CreateToken( SecurityTokenDescriptor tokenDescriptor )
        {
            if ( tokenDescriptor == null )
            {
                throw new ArgumentNullException( "tokenDescriptor" );
            }

            return CreateToken( tokenDescriptor.TokenIssuerName, tokenDescriptor.AppliesToAddress, tokenDescriptor.Subject, tokenDescriptor.Lifetime, tokenDescriptor.SigningCredentials );
        }
   
        /// <summary>
        /// Uses the <see cref="JwtSecurityToken(JwtHeader, JwtPayload, string )"/> constructor, first creating the <see cref="JwtHeader"/> and <see cref="JwtPayload"/>.
        /// <para>If <see cref="SigningCredentials"/> is not null, <see cref="JwtSecurityToken.RawData"/> will be signed.</para>
        /// </summary>
        /// <param name="issuer">the issuer of the token.</param>
        /// <param name="audience">the expected audience for this token</param>
        /// <param name="subject">the source of the <see cref="Claim"/>(s) for this token.</param>
        /// <param name="lifetime">the creation and expiration times for this token.</param>
        /// <param name="signingCredentials">contains cryptographic material for generating a signature.</param>
        /// <param name="signatureProvider">optional <see cref="SignatureProvider"/>.</param>
        /// <remarks>If <see cref="ClaimsIdentity.Actor"/> is not null, then a claim { actort, 'value' } will be added to the payload. <see cref="CreateActorValue"/> for details on how the value is created.
        /// <para>See <seealso cref="JwtHeader"/> for details on how the HeaderParameters are added to the header.</para>
        /// <para>See <seealso cref="JwtPayload"/> for details on how the values are added to the payload.</para></remarks>       
        /// <para>If signautureProvider is not null, then it will be used to create the signature and <see cref="System.IdentityModel.Tokens.SignatureProviderFactory.CreateForSigning( SecurityKey, string )"/> will not be called.</para>
        /// <returns>A <see cref="JwtSecurityToken"/>.</returns>
        public virtual JwtSecurityToken CreateToken( string issuer = null, string audience = null, ClaimsIdentity subject = null, Lifetime lifetime = null, SigningCredentials signingCredentials = null, SignatureProvider signatureProvider = null )
        {
            Lifetime lifetimeToUse = lifetime;
            if ( RequireExpirationTime )
            {
                if ( lifetimeToUse == null )
                {
                    lifetimeToUse = new Lifetime( null, new DateTime?( DateTimeUtil.Add( DateTime.UtcNow, TimeSpan.FromMinutes( DefaultTokenLifetimeInMinutes ) ) ) );
                }
                else if ( !lifetimeToUse.Expires.HasValue )
                {
                    if ( lifetimeToUse.Created.HasValue )
                    {
                        lifetimeToUse.Expires = new DateTime?( DateTimeUtil.Add( lifetimeToUse.Created.Value.ToUniversalTime(), TimeSpan.FromMinutes( DefaultTokenLifetimeInMinutes ) ) );
                    }
                    else
                    {
                        lifetimeToUse.Expires = new DateTime?( DateTimeUtil.Add( DateTime.UtcNow, TimeSpan.FromMinutes( DefaultTokenLifetimeInMinutes ) ) );
                    }
                }
            }

            JwtPayload payload = new JwtPayload( issuer, audience, subject == null ? null : subject.Claims, lifetimeToUse );
            JwtHeader  header  = new JwtHeader( signingCredentials );

            if ( subject != null && subject.Actor != null )
            {
                payload.AddClaim( new Claim( JwtConstants.ReservedClaims.Actor, CreateActorValue( subject.Actor ) ) );
            }

            string signature    = string.Empty;
            string signingInput = string.Concat( header.Encode(), ".", payload.Encode() );          

            if ( signingCredentials != null )
            {
                signature = Base64UrlEncoder.Encode( CreateSignature( signingInput, signingCredentials.SigningKey, signingCredentials.SignatureAlgorithm, signatureProvider ) );
            }

            return new JwtSecurityToken( header, payload, string.Concat( signingInput, ".", signature ) );
        }

        /// <summary>
        /// Gets the token type identifier(s) supported by this handler.
        /// </summary>
        /// <returns>A collection of strings that identify the tokens this instance can handle.</returns>
        /// <remarks>When receiving a <see cref=" JwtSecurityToken"/> wrapped inside a &lt;wsse:BinarySecurityToken> element. The &lt;wsse:BinarySecurityToken> element must have the ValueType attribute set to one of these values
        /// in order for this handler to recognize that it can read the token.</remarks>
        public override string[] GetTokenTypeIdentifiers()
        {
            return _tokenTypeIdentifiers;
        }
        
        /// <summary>
        /// Loads custom configuration from an <see cref="XmlNodeList"/>. Override this method to provide custom handling of elements.
        /// </summary>
        /// <param name="nodeList">The XML nodes that contain the custom configuration.</param>
        /// <remarks>A single element 'jwtSecurityTokenRequirement' is supported. See <see cref="System.IdentityModel.Tokens.JwtSecurityTokenRequirement(XmlElement)"/> for details.</remarks>
        /// <exception cref="ArgumentNullException">'nodelist' is null.</exception>
        /// <exception cref="ConfigurationErrorsException"><see cref="XmlNodeList"/> contains more than one element.</exception>
        /// <exception cref="ConfigurationErrorsException"><see cref="XmlElement.LocalName"/> != 'jwtSecurityTokenRequirement'.</exception>
        public override void LoadCustomConfiguration( XmlNodeList nodeList )
        {
            if ( nodeList == null )
            {
                throw new ArgumentNullException( "nodeList" );
            }

            List<XmlElement> elements = XmlUtil.GetXmlElements( nodeList );

            if ( elements.Count != 1 || !string.Equals( elements[0].LocalName, Elements.JwtSecurityTokenRequirement, StringComparison.Ordinal ) )
            {
                throw new ConfigurationErrorsException( string.Format( CultureInfo.InvariantCulture, JwtErrors.Jwt10601, elements[0].LocalName, elements[0].OuterXml ) );
            }

            _jwtSecurityTokenRequirement = new JwtSecurityTokenRequirement( elements[0] );
        }

        /// <summary>
        /// Reads a JSON web token wrapped inside a WS-Security BinarySecurityToken xml element.
        /// </summary>
        /// <returns>An instance of <see cref="JwtSecurityToken"/></returns>
        /// <remarks>First calls <see cref="JwtSecurityToken"/>.CanReadToken
        /// <para>The reader must be positioned at an element named:</para>
        /// <para>BinarySecurityToken'.
        /// in the namespace: 'http://docs.oasis-open.org/wss/2004/01/oasis-200401-wss-wssecurity-secext-1.0.xsd'
        /// with a 'ValueType' attribute equal to one of: "urn:ietf:params:oauth:token-type:jwt", "JWT".</para>
        /// <para>
        /// For example &lt;wsse:BinarySecurityToken valueType = "JWT"> ...
        /// </para>
        /// <para>
        /// The 'EncodingType' attribute is optional, if it is set, it must be equal to: "http://docs.oasis-open.org/wss/2004/01/oasis-200401-wss-soap-message-security-1.0#Base64Binary"
        /// </para>
        /// </remarks>
        /// <exception cref="ArgumentNullException">'reader' is null.</exception>
        /// <exception cref="ArgumentException">if <see cref="CanReadToken(XmlReader)"/> returns false.</exception>
        public override SecurityToken ReadToken( XmlReader reader )
        {
            if ( reader == null )
            {
                throw new ArgumentNullException( "reader" );
            }

            if ( !CanReadToken( reader ) )
            {
                throw new ArgumentException( 
                    string.Format( CultureInfo.InvariantCulture, 
                                   JwtErrors.Jwt10203, 
                                   GetType().ToString(),
                                   reader.ReadOuterXml(),
                                   WSSecurity10Constants.Elements.BinarySecurityToken,  
                                   WSSecurity10Constants.Namespace,
                                   WSSecurity10Constants.Attributes.ValueType,
                                   JwtConstants.TokenTypeAlt, 
                                   JwtConstants.TokenType ) );
            }

            XmlDictionaryReader dictionaryReader = XmlDictionaryReader.CreateDictionaryReader( reader );
            string wsuId    = dictionaryReader.GetAttribute( WSSecurityUtilityConstants.Attributes.Id, WSSecurityUtilityConstants.Namespace );
            JwtSecurityToken jwt = ReadToken( Encoding.UTF8.GetString( dictionaryReader.ReadElementContentAsBase64() ) ) as JwtSecurityToken;
            if ( wsuId != null )
            {
                jwt.SetId( wsuId );
            }

            return jwt;
        }

        /// <summary>
        /// Reads a token encoded in JSON Compact serialized format.
        /// </summary>
        /// <param name="jwtEncodedString">A 'JSON Web Token' (JWT) that has been encoded as a JSON object. May be signed 
        /// using 'JSON Web Signature' (JWS).</param>
        /// <remarks>
        /// The JWT must be encoded using Base64Url encoding of the UTF-8 representation of the JWT: Header, Payload and Signature. 
        /// The contents of the JWT returned are not validated in any way, the token is simply decoded. Use ValidateToken to validate the JWT.
        /// </remarks>
        public override SecurityToken ReadToken( string jwtEncodedString )
        {
            if ( jwtEncodedString == null )
            {
                throw new ArgumentNullException( "jwtEncodedString" );
            }

            if ( jwtEncodedString.Length * 2 > MaxTokenSizeInBytes )
            {
                throw new ArgumentException( string.Format( CultureInfo.InvariantCulture, JwtErrors.Jwt10206, jwtEncodedString.Length, MaxTokenSizeInBytes ) );
            }

            if ( !CanReadToken( jwtEncodedString ) )
            {
                throw new ArgumentException( string.Format( CultureInfo.InvariantCulture, JwtErrors.Jwt10204, GetType(), jwtEncodedString ) );
            }

            return new JwtSecurityToken( jwtEncodedString );
        }

        /// <summary>
        /// Produces a signature over the 'input' using the <see cref="SecurityKey"/> and algorithm specified.
        /// </summary>
        /// <param name="inputString">string to be signed</param>
        /// <param name="key">the <see cref="SecurityKey"/> to use.</param>
        /// <param name="algorithm">the algorithm to use.</param>
        /// <param name="signatureProvider">signature provider</param>
        /// <returns>The signature over the bytes obtained from UTF8Encoding.GetBytes( 'input' ).</returns>
        /// <remarks>The <see cref="SignatureProvider"/> used to created the signature is obtained by calling <see cref="System.IdentityModel.Tokens.SignatureProviderFactory.CreateForSigning(SecurityKey, string)"/>.</remarks>
        /// <exception cref="ArgumentNullException">'input' is null.</exception>
        /// <exception cref="InvalidProgramException"><see cref="System.IdentityModel.Tokens.SignatureProviderFactory.CreateForSigning(SecurityKey, string)"/> returns null.</exception>
        internal byte[] CreateSignature( string inputString, SecurityKey key, string algorithm, SignatureProvider signatureProvider = null )
        {
            if ( null == inputString )
            {
                throw new ArgumentNullException( "inputString" );
            }

            SignatureProvider provider;
            if ( signatureProvider != null )
            {
                return signatureProvider.Sign( Encoding.UTF8.GetBytes( inputString ) );
            }
            else
            {
                provider = SignatureProviderFactory.CreateForSigning( key, algorithm );
                if ( provider == null )
                {
                    throw new InvalidProgramException( string.Format( CultureInfo.InvariantCulture, JwtErrors.Jwt10331, SignatureProviderFactory.GetType(), typeof( SignatureProvider ), key == null ? "<null>" : key.GetType().ToString(), algorithm == null ? "<null>" : algorithm ) );
                }

                byte[] bytes = provider.Sign( Encoding.UTF8.GetBytes( inputString ) );
                SignatureProviderFactory.ReleaseProvider( provider );
                return bytes;
            }
        }

        /// <summary>
        /// Creates the 'value' for the actor claim: { actort, 'value' }
        /// </summary>
        /// <param name="actor"><see cref="ClaimsIdentity"/> as actor.</param>
        /// <returns><see cref="string"/> representing the actor.</returns>
        /// <remarks>If <see cref="ClaimsIdentity.BootstrapContext"/> is not null:
        /// <para>&#160;&#160;if 'type' is 'string', return as string.</para>
        /// <para>&#160;&#160;if 'type' is 'BootstrapContext' and 'BootstrapContext.SecurityToken' is 'JwtSecurityToken'</para>
        /// <para>&#160;&#160;&#160;&#160;if 'JwtSecurityToken.RawData' != null, return RawData.</para>        
        /// <para>&#160;&#160;&#160;&#160;else return <see cref="JwtSecurityTokenHandler.WriteToken( SecurityToken )"/>.</para>        
        /// <para>&#160;&#160;if 'BootstrapContext.Token' != null, return 'Token'.</para>
        /// <para>default: <see cref="JwtSecurityTokenHandler.WriteToken(SecurityToken)"/> new ( <see cref="JwtSecurityToken"/>( actor.Claims ).</para>
        /// </remarks>
        /// <exception cref="ArgumentNullException">'actor' is null.</exception>
        protected virtual string CreateActorValue( ClaimsIdentity actor )
        {
            if ( actor == null )
            {
                throw new ArgumentNullException( "actor" );
            }

            if ( actor.BootstrapContext != null )
            {
                string encodedJwt = actor.BootstrapContext as string;
                if ( encodedJwt != null )
                {
                    return encodedJwt;
                }

                BootstrapContext bootstrapContext = actor.BootstrapContext as BootstrapContext;
                if ( bootstrapContext != null )
                {
                    JwtSecurityToken jwt = bootstrapContext.SecurityToken as JwtSecurityToken;
                    if ( jwt != null )
                    {
                        if ( jwt.RawData != null )
                        {
                            return jwt.RawData;
                        }
                        else
                        {
                            return this.WriteToken( jwt );
                        }
                    }

                    if ( bootstrapContext.Token != null )
                    {
                        return bootstrapContext.Token;
                    }
                }
            }

            return WriteToken( new JwtSecurityToken( claims: actor.Claims ) );
        }

        /// <summary>
        /// Validates that <see cref="JwtSecurityToken.Audience"/> is an expected value.
        /// </summary>       
        /// <param name="jwt">The <see cref="JwtSecurityToken"/> to validate.</param>
        /// <remarks><para>If <see cref="AudienceRestriction.AudienceMode"/> == <see cref="AudienceUriMode.Never"/> OR  <para>( <see cref="AudienceUriMode"/> == <see cref="AudienceUriMode.BearerKeyOnly"/>  AND  <see cref="JwtSecurityToken.SecurityKeys"/>.Count == 0 ) </para><para>then validation is skipped.</para></para>
        /// <para>If validation is performed, <see cref="JwtSecurityToken.Audience"/> is compared to each <see cref="Uri"/> in <see cref="SecurityTokenHandlerConfiguration.AudienceRestriction"/>.AllowedAudienceUris by comparing to <see cref="Uri.OriginalString"/>. Returns when first compare succeeds.  Compare is performed using <see cref="StringComparison"/>.Ordinal (case sensitive).</para></remarks>
        /// <exception cref="ArgumentNullException">'jwt' is null.</exception>
        /// <exception cref="InvalidOperationException"><see cref="SecurityTokenHandler.Configuration"/> is null.</exception>
        /// <exception cref="InvalidOperationException"><see cref="SecurityTokenHandler.Configuration"/>.AudienceRestriction is null.</exception>
        /// <exception cref="AudienceUriValidationFailedException">if <see cref="string.IsNullOrWhiteSpace"/>( <see cref="JwtSecurityToken.Audience"/> ) is true.</exception>
        /// <exception cref="AudienceUriValidationFailedException"><see cref="JwtSecurityToken.Audience"/> fails to match one of <see cref="AudienceRestriction.AllowedAudienceUris"/>.</exception>
        protected virtual void ValidateAudience( JwtSecurityToken jwt )
        {
            if ( jwt == null )
            {
                throw new ArgumentNullException( "jwt" );
            }

            if ( Configuration == null )
            {
                throw new InvalidOperationException( JwtErrors.Jwt10205 );
            }

            if ( Configuration.AudienceRestriction == null )
            {
                throw new InvalidOperationException( JwtErrors.Jwt10328 );
            }

            // return if we shouldn't check
            if ( ( Configuration.AudienceRestriction.AudienceMode == AudienceUriMode.Never ) ||
                 ( Configuration.AudienceRestriction.AudienceMode == AudienceUriMode.BearerKeyOnly && jwt.SecurityKeys.Count > 0 ) )
            {
                return;
            }

            if ( string.IsNullOrWhiteSpace( jwt.Audience ) )
            {
                throw new AudienceUriValidationFailedException( string.Format( CultureInfo.InvariantCulture, JwtErrors.Jwt10300 ) );
            }

            foreach ( Uri uri in Configuration.AudienceRestriction.AllowedAudienceUris )
            {
                if ( string.Equals( uri.OriginalString, jwt.Audience, StringComparison.Ordinal ) )
                {
                    return;
                }
            }

            throw new AudienceUriValidationFailedException( string.Format( CultureInfo.InvariantCulture, JwtErrors.Jwt10332, jwt.Audience ) );
        }

        /// <summary>
        /// Validates that <see cref="JwtSecurityToken.Audience"/> is an expected value.
        /// </summary>       
        /// <param name="jwt">The <see cref="JwtSecurityToken"/> to validate.</param>
        /// <param name="validationParameters">Contains valid audiences.</param>
        /// <remarks><para>If <see cref="AudienceRestriction.AudienceMode"/> == <see cref="AudienceUriMode.Never"/> OR  <para>( <see cref="AudienceUriMode"/> == <see cref="AudienceUriMode.BearerKeyOnly"/>  AND  <see cref="JwtSecurityToken.SecurityKeys"/>.Count == 0 ) </para><para>then validation is skipped.</para></para>
        /// <para>If validation is performed, <see cref="JwtSecurityToken.Audience"/> is compared first to <see cref="TokenValidationParameters.AllowedAudience"/> and then to each string in <see cref="TokenValidationParameters.AllowedAudiences"/>. Returns when first compare succeeds. Compare is performed using <see cref="StringComparison"/>.Ordinal (case sensitive).</para></remarks>
        /// <exception cref="ArgumentNullException">'jwt' is null.</exception>
        /// <exception cref="ArgumentNullException">'validationParameters' is null.</exception>
        /// <exception cref="SecurityTokenValidationException">if <see cref="string.IsNullOrWhiteSpace"/>( <see cref="JwtSecurityToken.Audience"/> ) is true.</exception>
        /// <exception cref="ArgumentException">'<see cref="TokenValidationParameters.AllowedAudience"/>' is null or whitespace AND <see cref="TokenValidationParameters.AllowedAudiences"/> is null.</exception>
        /// <exception cref="AudienceUriValidationFailedException"><see cref="JwtSecurityToken.Audience"/> fails to match <see cref="TokenValidationParameters.AllowedAudience"/> or one of <see cref="TokenValidationParameters.AllowedAudiences"/>.</exception>
        protected virtual void ValidateAudience( JwtSecurityToken jwt, TokenValidationParameters validationParameters )
        {
            if ( jwt == null )
            {
                throw new ArgumentNullException( "jwt" );
            }

            if ( validationParameters == null )
            {
                throw new ArgumentNullException( "validationParameters" );
            }

            if ( ( validationParameters.AudienceUriMode == AudienceUriMode.Never ) ||
                 ( validationParameters.AudienceUriMode == AudienceUriMode.BearerKeyOnly && jwt.SecurityKeys.Count > 0 ) )
            {
                return;
            }

            if ( string.IsNullOrWhiteSpace( jwt.Audience ) )
            {
                throw new AudienceUriValidationFailedException( string.Format( CultureInfo.InvariantCulture, JwtErrors.Jwt10300 ) );
            }

            if ( string.IsNullOrWhiteSpace( validationParameters.AllowedAudience ) && ( validationParameters.AllowedAudiences == null ) )
            {
                throw new ArgumentException( string.Format( CultureInfo.InvariantCulture, JwtErrors.Jwt10301 ) );
            }

            if ( !string.IsNullOrWhiteSpace( validationParameters.AllowedAudience ) )
            {
                if ( string.Equals( validationParameters.AllowedAudience, jwt.Audience, StringComparison.Ordinal ) )
                {
                    return;
                }
            }

            if ( validationParameters.AllowedAudiences != null )
            {
                foreach ( string str in validationParameters.AllowedAudiences )
                {
                    if ( string.Equals( str, jwt.Audience, StringComparison.Ordinal ) )
                    {
                        return;
                    }
                }
            }

            throw new AudienceUriValidationFailedException( string.Format( CultureInfo.InvariantCulture, JwtErrors.Jwt10303, jwt.Audience, validationParameters.AllowedAudience ?? "null", Utility.SerializeAsSingleCommaDelimitedString( validationParameters.AllowedAudiences ) ) );
        }

        /// <summary>
        /// Validates <see cref="JwtSecurityToken.ValidFrom"/> and <see cref="JwtSecurityToken.ValidTo"/>.
        /// </summary>
        /// <param name="jwt">The <see cref="JwtSecurityToken"/> to validate.</param>
        /// <remarks>
        /// <see cref="JwtSecurityTokenHandler.RequireExpirationTime"/> mandates if claim { exp, 'value' } is required. Default is true.
        /// <para>If the <see cref="JwtSecurityToken"/> contains the claim { exp, 'value' } it will be validated regardless of <see cref="JwtSecurityTokenHandler.RequireExpirationTime"/>.</para>
        /// <para>If the <see cref="JwtSecurityToken"/> contains the claim { nbf, 'value' } it will be validated.</para>
        /// <para><see cref="JwtSecurityTokenHandler.MaxClockSkew"/> is applied.</para>
        /// </remarks>
        /// <exception cref="ArgumentNullException">'jwt' is null.</exception>
        /// <exception cref="SecurityTokenValidationException"><see cref="JwtSecurityToken"/> does not contain the claim { exp, 'value' } and <see cref="JwtSecurityTokenHandler.RequireExpirationTime"/> is true.</exception>
        /// <exception cref="SecurityTokenValidationException"><see cref="JwtSecurityToken.ValidFrom"/> is after <see cref="JwtSecurityToken.ValidTo"/>.</exception>
        /// <exception cref="SecurityTokenValidationException"><see cref="JwtSecurityToken.ValidFrom"/> is after <see cref="DateTime.UtcNow"/>.</exception>
        /// <exception cref="SecurityTokenValidationException"><see cref="JwtSecurityToken.ValidTo"/> is after <see cref="DateTime.UtcNow"/>.</exception>
        protected virtual void ValidateLifetime( JwtSecurityToken jwt )
        {
            if ( jwt == null )
            {
                throw new ArgumentNullException( "jwt" );
            }

            bool nbfExists = false;
            bool expExists = false;
            object obj = null;

            nbfExists = jwt.Payload.TryGetValue( JwtConstants.ReservedClaims.NotBefore, out obj );
            expExists = jwt.Payload.TryGetValue( JwtConstants.ReservedClaims.ExpirationTime, out obj );
            if ( !expExists && RequireExpirationTime )
            {
                throw new SecurityTokenValidationException( string.Format( CultureInfo.InvariantCulture, JwtErrors.Jwt10322, jwt ) );
            }

            if ( nbfExists && expExists && ( jwt.ValidFrom > jwt.ValidTo ) )
            {
                throw new SecurityTokenValidationException( string.Format( CultureInfo.InvariantCulture, JwtErrors.Jwt10403, jwt.ValidFrom, jwt.ValidTo ) );
            }

            DateTime utcNow = DateTime.UtcNow;
            if ( nbfExists && ( jwt.ValidFrom > DateTimeUtil.Add( utcNow, MaxClockSkew ) ) )
            {
                throw new SecurityTokenValidationException( string.Format( CultureInfo.InvariantCulture, JwtErrors.Jwt10306, jwt.ValidFrom, utcNow ) );
            }

            if ( expExists && ( jwt.ValidTo < DateTimeUtil.Add( utcNow, MaxClockSkew.Negate() ) ) )
            {
                throw new SecurityTokenValidationException( string.Format( CultureInfo.InvariantCulture, JwtErrors.Jwt10305, jwt.ValidTo, utcNow ) );
            }
        }

        /// <summary>
        /// Validates that <see cref="JwtSecurityToken.Issuer"/> is an expected value.
        /// </summary>
        /// <param name="jwt">The <see cref="JwtSecurityToken"/> to validate.</param>
        /// <remarks>Calls <see cref="Configuration"/>.IssuerNameRegistry.GetIssuerName( jwt, jwt.Issuer ).</remarks>
        /// <returns>The <see cref="string"/> to use when creating a <see cref="Claim"/>, <see cref="Claim.Issuer"/> will be equal to this value.</returns>
        /// <exception cref="ArgumentNullException">'jwt' is null.</exception>
        /// <exception cref="SecurityTokenValidationException">if <see cref="string.IsNullOrWhiteSpace"/>( <see cref="JwtSecurityToken.Issuer"/> ) is true.</exception>
        /// <exception cref="InvalidOperationException"><see cref="Configuration"/> is null.</exception>
        /// <exception cref="InvalidOperationException"><see cref="Configuration"/>.IssuerNameRegistry is null.</exception>
        /// <exception cref="SecurityTokenValidationException">The 'value' returned <see cref="Configuration"/>.IssuerNameRegistry.GetIssuerName is null or empty.</exception>
        protected virtual string ValidateIssuer( JwtSecurityToken jwt )
        {
            if ( jwt == null )
            {
                throw new ArgumentNullException( "jwt" );
            }

            if ( string.IsNullOrWhiteSpace( jwt.Issuer ) )
            {
                throw new SecurityTokenValidationException( string.Format( CultureInfo.InvariantCulture, JwtErrors.Jwt10319 ) );
            }

            if ( Configuration == null )
            {
                throw new InvalidOperationException( JwtErrors.Jwt10205 );
            }

            if ( Configuration.IssuerNameRegistry == null )
            {
                throw new InvalidOperationException( JwtErrors.Jwt10330 );
            }

            string issuer = Configuration.IssuerNameRegistry.GetIssuerName( jwt.SigningToken, jwt.Issuer );
            if ( string.IsNullOrEmpty( issuer ) )
            {
                throw new SecurityTokenValidationException( string.Format( CultureInfo.InvariantCulture, JwtErrors.Jwt10318, jwt.Issuer ) );
            }

            return issuer;
        }

        /// <summary>
        /// Validates that <see cref="JwtSecurityToken.Issuer"/> is an expected value.
        /// </summary>
        /// <param name="jwt">The <see cref="JwtSecurityToken"/> to validate.</param>
        /// <param name="validationParameters">Contains valid issuers.</param>
        /// <exception cref="ArgumentNullException">'jwt' is null.</exception>
        /// <exception cref="ArgumentNullException">'validationParameters' is null.</exception>
        /// <exception cref="SecurityTokenValidationException">if <see cref="string.IsNullOrWhiteSpace"/>( <see cref="JwtSecurityToken.Issuer"/> ) is true.</exception>
        /// <exception cref="ArgumentException"><see cref="TokenValidationParameters.ValidIssuer"/> is null or whitespace AND <see cref="TokenValidationParameters.ValidIssuers"/> is null.</exception>
        /// <exception cref="SecurityTokenValidationException"><see cref="JwtSecurityToken.Issuer"/> fails to match <see cref="TokenValidationParameters.ValidIssuer"/> or one of <see cref="TokenValidationParameters.ValidIssuers"/>.</exception>
        protected virtual string ValidateIssuer( JwtSecurityToken jwt, TokenValidationParameters validationParameters )
        {
            if ( jwt == null )
            {
                throw new ArgumentNullException( "jwt" );
            }

            if ( validationParameters == null )
            {
                throw new ArgumentNullException( "validationParameters" );
            }

            if ( string.IsNullOrWhiteSpace( jwt.Issuer ) )
            {
                throw new SecurityTokenValidationException( string.Format( CultureInfo.InvariantCulture, JwtErrors.Jwt10319 ) );
            }

            if ( !validationParameters.ValidateIssuer )
            {
                return jwt.Issuer;
            }

            // Throw if all possible places to validate against are null or empty
            if ( string.IsNullOrWhiteSpace( validationParameters.ValidIssuer ) && ( validationParameters.ValidIssuers == null ) )
            {
                throw new ArgumentException( string.Format( CultureInfo.InvariantCulture, JwtErrors.Jwt10317 ) );
            }

            if (!string.IsNullOrWhiteSpace( validationParameters.ValidIssuer) && string.Equals( validationParameters.ValidIssuer, jwt.Issuer, StringComparison.Ordinal ) )
            {
                return jwt.Issuer;
            }

            if ( null != validationParameters.ValidIssuers)
            {
                foreach( string str in validationParameters.ValidIssuers )
                {
                    if ( string.Equals( str, jwt.Issuer, StringComparison.Ordinal ) )
                    {
                        return jwt.Issuer;
                    }
                }
            }

            string validIssuer = validationParameters.ValidIssuer ?? "null";
            string validIssuers = validationParameters.ValidIssuers == null ? "null" : Utility.SerializeAsSingleCommaDelimitedString( validationParameters.ValidIssuers );

            throw new SecurityTokenValidationException( string.Format( CultureInfo.InvariantCulture, JwtErrors.Jwt10311, validIssuer, validIssuers, jwt.Issuer ) );
        }

        /// <summary>
        /// Validates the signature of a <see cref="JwtSecurityToken"/>
        /// </summary>
        /// <param name="jwt"><see cref="JwtSecurityToken"/> to validate.</param>
        /// <remarks>If validation is successful, <see cref="JwtSecurityToken.SigningToken"/> and <see cref="JwtSecurityToken.SigningKey"/> 
        /// will be set to the <see cref="SecurityToken"/> and <see cref="SecurityKey"/> the validated the signature.</remarks>
        /// <exception cref="ArgumentNullException">'jwt' is null.</exception>
        /// <exception cref="InvalidOperationException"><see cref="JwtSecurityTokenHandler"/>.Configuration is null.</exception>
        /// <exception cref="InvalidOperationException"><see cref="JwtSecurityTokenHandler"/>.Configuration.IssuerTokenResolver is null.</exception>
        /// <exception cref="SecurityTokenValidationException"><see cref="SecurityTokenResolver.ResolveToken( SecurityKeyIdentifier )"/> returns null.</exception>
        /// <exception cref="SecurityTokenValidationException">signature is not valid.</exception>
        protected virtual void ValidateSignature( JwtSecurityToken jwt )
        {
            if ( jwt == null )
            {
                throw new ArgumentNullException( "jwt" );
            }

            byte[] signatureBytes = Base64UrlEncoder.DecodeBytes( jwt.EncodedSignature );

            if ( signatureBytes.Length == 0 )
            {
                if ( !RequireSignedTokens )
                {
                    return;
                }

                throw new SecurityTokenValidationException( string.Format( CultureInfo.InvariantCulture, JwtErrors.Jwt10312, jwt.RawData ) );
            }

            if ( string.Equals( jwt.Header.SignatureAlgorithm, JwtConstants.Algorithms.NONE, StringComparison.Ordinal ) )
            {
                if ( !RequireSignedTokens )
                {
                    return;
                }

                throw new SecurityTokenValidationException( string.Format( CultureInfo.InvariantCulture, JwtErrors.Jwt10320, JwtConstants.Algorithms.NONE, jwt.RawData ) );
            }

            if ( Configuration == null )
            {
                throw new InvalidOperationException( JwtErrors.Jwt10205 );
            }

            if ( Configuration.IssuerTokenResolver == null )
            {
                throw new InvalidOperationException( JwtErrors.Jwt10328 );
            }

            SecurityKeyIdentifier ski = jwt.Header.SigningKeyIdentifier;
            SecurityToken signingToken = null;
            NamedKeyIssuerTokenResolver namedKeyResolver = Configuration.IssuerTokenResolver as NamedKeyIssuerTokenResolver;

            // Add a NamedKeyIssuerClause from the 'iss' claim if issuer exists.
            if ( namedKeyResolver != null && jwt.Issuer != null )
            {
                ski.Add( new NamedKeySecurityKeyIdentifierClause( jwt.Issuer, JwtConstants.ReservedClaims.Issuer ) );
            }

            Configuration.IssuerTokenResolver.TryResolveToken( ski, out signingToken );
            if ( signingToken == null )
            {
                throw new SecurityTokenValidationException( string.Format( CultureInfo.InvariantCulture, JwtErrors.Jwt10329, ski ) );
            }

            ValidateSignature( jwt, signatureBytes, new List<SecurityToken>() { signingToken } );
        }

        /// <summary>
        /// Validates that the signature is valid.
        /// </summary>
        /// <param name="jwt"><see cref="JwtSecurityToken"/> to validate.</param>
        /// <param name="validationParameters">contains <see cref="SecurityToken"/>(s) used to check signature.</param>
        /// <remarks>If validation is successful, <see cref="JwtSecurityToken.SigningToken"/> and <see cref="JwtSecurityToken.SigningKey"/> 
        /// will be set to the <see cref="SecurityToken"/> and <see cref="SecurityKey"/> the validated the signature.</remarks>
        /// <exception cref="ArgumentNullException">'jwt' is null.</exception>
        /// <exception cref="ArgumentNullException">'validationParameters' is null.</exception>
        /// <exception cref="InvalidOperationException"><see cref="TokenValidationParameters.SigningToken"/> and <see cref="TokenValidationParameters.SigningTokens"/> are both null.</exception>
        /// <exception cref="SecurityTokenValidationException">signature is not valid.</exception>
        protected virtual void ValidateSignature( JwtSecurityToken jwt, TokenValidationParameters validationParameters )
        {
            if ( jwt == null )
            {
                throw new ArgumentNullException( "jwt" );
            }

            if ( validationParameters == null )
            {
                throw new ArgumentNullException( "validationParameters" );
            }

            byte[] signatureBytes = Base64UrlEncoder.DecodeBytes( jwt.EncodedSignature );

            if ( signatureBytes.Length == 0 )
            {
                if ( !RequireSignedTokens )
                {
                    return;
                }

                throw new SecurityTokenValidationException( string.Format( CultureInfo.InvariantCulture, JwtErrors.Jwt10312, jwt.RawData ) );
            }

            if ( string.Equals( jwt.Header.SignatureAlgorithm, JwtConstants.Algorithms.NONE, StringComparison.Ordinal ) )
            {
                if ( !RequireSignedTokens )
                {
                    return;
                }

                throw new SecurityTokenValidationException( string.Format( CultureInfo.InvariantCulture, JwtErrors.Jwt10320, JwtConstants.Algorithms.NONE, jwt.RawData ) );
            }

            if ( validationParameters.SigningToken == null && validationParameters.SigningTokens == null )
            {
                throw new InvalidOperationException( JwtErrors.Jwt10309 );
            }

            if ( validationParameters.SigningToken == null )
            {
                ValidateSignature( jwt, signatureBytes, validationParameters.SigningTokens );
            }
            else if ( validationParameters.SigningTokens == null )
            {
                ValidateSignature( jwt, signatureBytes, new SecurityToken[] { validationParameters.SigningToken } );
            }
            else
            {
                List<SecurityToken> tokens = new List<SecurityToken>( validationParameters.SigningTokens );
                tokens.Add( validationParameters.SigningToken );
                ValidateSignature( jwt, signatureBytes, tokens );
            }
        }

        /// <summary>
        /// Validates that the signature, if found and / or required is valid.
        /// </summary>
        /// <param name="jwt">the <see cref="JwtSecurityToken"/> to validate.</param>
        /// <param name="signatureBytes">Base64urlDecoded bytes.</param>
        /// <param name="signingTokens">contains the <see cref="SecurityToken"/>(s) that contain <see cref="SecurityKey"/>(s) used to check the signature.</param>
        internal void ValidateSignature( JwtSecurityToken jwt, byte[] signatureBytes, IEnumerable<SecurityToken> signingTokens )
        {

            string mappedAlgorithm = jwt.SignatureAlgorithm;
            if ( mappedAlgorithm != null && InboundAlgorithmMap.ContainsKey( mappedAlgorithm ) )
            {
                mappedAlgorithm = InboundAlgorithmMap[mappedAlgorithm];
            }

            // maintain a list of all the exceptions that were thrown, display them to the user at the end.
            List< Exception > exceptions = new List<Exception>();
            int numNonNullKeysTried = 0;
            byte[] encodedBytes = Encoding.UTF8.GetBytes( jwt.EncodedHeader + '.' + jwt.EncodedPayload );

            List<SecurityKey> keysTried = new List<SecurityKey>();

            // run through all the tokens, actively searching for a clause match
            foreach ( SecurityToken securityToken in signingTokens )
            {
                foreach ( SecurityKeyIdentifierClause clause in jwt.Header.SigningKeyIdentifier )
                {
                    SecurityKey resolvedSecurityKey = securityToken.ResolveKeyIdentifierClause( clause );
                    if ( resolvedSecurityKey != null )
                    {
                        keysTried.Add( resolvedSecurityKey );
                        numNonNullKeysTried++;

                        try
                        {
                            if ( ValidateSignature( resolvedSecurityKey, mappedAlgorithm, encodedBytes, signatureBytes ) )
                            {
                                jwt.SigningKey = resolvedSecurityKey;
                                jwt.SigningToken = securityToken;
                                return;
                            }
                        }
                        catch ( Exception ex )
                        {
                            if ( DiagnosticUtility.IsFatal( ex ) )
                            {
                                throw;
                            }

                            exceptions.Add( ex );
                        }
                    }
                }
            }

            // run through all the tokens, skipping keys we tried already
            foreach ( SecurityToken securityToken in signingTokens )
            {
                foreach ( SecurityKey key in securityToken.SecurityKeys )
                {
                    if ( keysTried.Contains( key ) )
                    {
                        continue;
                    }

                    try
                    {
                        if ( key != null )
                        {
                            keysTried.Add( key );
                        }

                        if ( ValidateSignature( key, mappedAlgorithm, encodedBytes, signatureBytes ) )
                        {
                            jwt.SigningKey = key;
                            jwt.SigningToken = securityToken;
                            return;
                        }
                    }
                    catch ( Exception ex )
                    {
                        if ( DiagnosticUtility.IsFatal( ex ) )
                        {
                            throw;
                        }

                        exceptions.Add( ex );
                    }
                }
            }
            
            string keysAttempted = string.Empty;
            if ( keysTried.Count == 0 )
            {
                keysAttempted = JwtErrors.NoNonNullKeysFound;
            }
            else
            {
                bool first = true;
                foreach ( SecurityKey key in keysTried )
                {
                    if ( !first && key != null )
                    {
                        keysAttempted += "\n";
                        first = false;
                    }

                    keysAttempted += key.ToString();
                }

                keysAttempted = string.Format( CultureInfo.InvariantCulture, JwtErrors.KeysTried, keysAttempted );
            }

            if ( null != exceptions && exceptions.Count > 0 )
            {
                bool first = true;
                StringBuilder sb = new StringBuilder();
                foreach ( Exception ex in exceptions )
                {
                    if ( !first )
                    {
                        sb.Append( "\n" );
                        first = false;
                    }

                    sb.AppendLine( ex.ToString() );
                }

                throw new SecurityTokenValidationException( string.Format( CultureInfo.InvariantCulture, JwtErrors.Jwt10316, keysAttempted, sb.ToString(), jwt.ToString() ) );
            }
            else
            {
                throw new SecurityTokenValidationException( string.Format( CultureInfo.InvariantCulture, JwtErrors.Jwt10315, keysAttempted, jwt.ToString() ) );
            }
        }

        internal bool ValidateSignature( SecurityKey key, string algorithm, byte[] encodedBytes, byte[] signature )
        {
            // in the case that a SignatureProviderFactory can handle nulls, just don't check here.
            SignatureProvider signatureProvider = SignatureProviderFactory.CreateForVerifying( key, algorithm );
            if ( signatureProvider == null )
            {
                throw new InvalidOperationException( string.Format( CultureInfo.InvariantCulture, JwtErrors.Jwt10314, key == null ? TextStrings.Null : key.ToString(), algorithm == null ? TextStrings.Null : algorithm ) );
            }

            return signatureProvider.Verify( encodedBytes, signature );
        }

        /// <summary>
        /// Validates the <see cref="JwtSecurityToken.SigningToken"/> is an expected value.
        /// </summary>
        /// <param name="jwt">The <see cref="JwtSecurityToken"/> to validate.</param>
        /// <remarks>If the <see cref="JwtSecurityToken.SigningToken"/> is a <see cref="X509SecurityToken"/> then the X509Certificate2 will be validated using <see cref="JwtSecurityTokenHandler.CertificateValidator"/>.</remarks>
        protected virtual void ValidateSigningToken( JwtSecurityToken jwt )
        {
            X509SecurityToken x509SecurityToken = jwt.SigningToken as X509SecurityToken;
            if ( x509SecurityToken != null )
            {
                CertificateValidator.Validate( x509SecurityToken.Certificate );
            }
        }

        /// <summary>
        /// Validates a <see cref="JwtSecurityToken"/> and returns <see cref="ReadOnlyCollection{ClaimsIdentity}"/>.
        /// </summary>
        /// <param name="token">The <see cref="JwtSecurityToken"/> to validate.</param>
        /// <remarks>Calls <see cref="ValidateToken( JwtSecurityToken )"/>.</remarks>
        /// <exception cref="ArgumentNullException">'token' is null.</exception>
        /// <exception cref="ArgumentException">'token' is not a <see cref="JwtSecurityToken"/>.</exception>
        public override ReadOnlyCollection<ClaimsIdentity> ValidateToken( SecurityToken token )
        {
            if ( token == null )
            {
                throw new ArgumentNullException( "token" );
            }

            JwtSecurityToken jwt = token as JwtSecurityToken;
            if ( jwt == null )
            {
                throw new ArgumentException( string.Format( CultureInfo.InvariantCulture, JwtErrors.Jwt10308, typeof( JwtSecurityToken ), token.GetType() ) );
            }

            return ( new List<ClaimsIdentity>( ValidateToken( jwt ).Identities ) ).AsReadOnly();
        }

        /// <summary>
        /// Reads and validates a token encoded in JSON Compact serialized format.
        /// </summary>
        /// <param name="jwtEncodedString">A 'JSON Web Token' (JWT) that has been encoded as a JSON object. May be signed 
        /// using 'JSON Web Signature' (JWS).</param>
        /// <remarks>
        /// <para>Calls <see cref="JwtSecurityTokenHandler.ValidateToken( JwtSecurityToken )"/>.</para>
        /// To obtain the <see cref="JwtSecurityToken"/>, <see cref="JwtSecurityTokenHandler.ReadToken( string )"/> is called.
        /// </remarks>
        /// <exception cref="ArgumentNullException">'jwtEncodedString' is null.</exception>
        public virtual ClaimsPrincipal ValidateToken( string jwtEncodedString )
        {
            if ( jwtEncodedString == null )
            {
                throw new ArgumentNullException( "jwtEncodedString" );
            }

            JwtSecurityToken jwt = ReadToken( jwtEncodedString ) as JwtSecurityToken;
            return ValidateToken( jwt );
        }

        /// <summary>
        /// Reads and validates a token encoded in JSON Compact serialized format.
        /// </summary>
        /// <param name="jwtEncodedString">A 'JSON Web Token' (JWT) that has been encoded as a JSON object. May be signed 
        /// using 'JSON Web Signature' (JWS).</param>
        /// <param name="validationParameters">Contains validation parameters for the <see cref="JwtSecurityToken"/>.</param>
        /// <remarks>
        /// <para>Calls <see cref="JwtSecurityTokenHandler.ValidateToken( JwtSecurityToken, TokenValidationParameters )"/>.</para>
        /// To obtain the <see cref="JwtSecurityToken"/>, <see cref="JwtSecurityTokenHandler.ReadToken( string )"/> is called.
        /// </remarks>
        /// <exception cref="ArgumentNullException">'jwtEncodedString' is null.</exception>
        /// <exception cref="ArgumentNullException">'validationParameters' is null.</exception>        
        public virtual ClaimsPrincipal ValidateToken( string jwtEncodedString, TokenValidationParameters validationParameters )
        {
            if ( jwtEncodedString == null )
            {
                throw new ArgumentNullException( "jwtEncodedString" );
            }

            if ( validationParameters == null )
            {
                throw new ArgumentNullException( "validationParameters" );
            }

            JwtSecurityToken jwt = ReadToken( jwtEncodedString ) as JwtSecurityToken;
            return ValidateToken( jwt, validationParameters );
        }

        /// <summary>
        /// Validates a <see cref="JwtSecurityToken"/> and returns a <see cref="ClaimsPrincipal"/>.
        /// </summary>
        /// <param name="jwt">The <see cref="JwtSecurityToken"/> to validate.</param>
        /// <remarks>
        /// <para>Validation calls , in sequence the following protected virtual methods:</para>
        /// <para><see cref="ValidateSignature( JwtSecurityToken )"/></para>
        /// <para><see cref="ValidateSigningToken( JwtSecurityToken )"/></para>
        /// <para><see cref="ValidateAudience( JwtSecurityToken )"/>(</para>
        /// <para><see cref="ValidateLifetime( JwtSecurityToken )"/>(</para>
        /// <para><see cref="ValidateIssuer( JwtSecurityToken )"/>(</para>
        /// </remarks>
        /// <exception cref="ArgumentNullException">'jwt' is null.</exception>
        public virtual ClaimsPrincipal ValidateToken( JwtSecurityToken jwt )
        {
            if ( jwt == null )
            {
                throw new ArgumentNullException( "jwt" );
            }

            ValidateSignature( jwt );
            ValidateSigningToken( jwt );
            ValidateLifetime( jwt );
            ValidateAudience( jwt );
            return new ClaimsPrincipal( ClaimsIdentityFromJwt( jwt, ValidateIssuer( jwt ), Configuration.SaveBootstrapContext ) );
        }

        /// <summary>
        /// Validates a <see cref="JwtSecurityToken"/> and returns a <see cref="ClaimsPrincipal"/>.
        /// </summary>
        /// <param name="jwt">The <see cref="JwtSecurityToken"/> to validate.</param>
        /// <param name="validationParameters">Contains validation parameters for the <see cref="JwtSecurityToken"/>.</param>
        /// <remarks>
        /// <para>Validation calls, in sequence, the following protected virtual methods:</para>
        /// <para><see cref="ValidateSignature( JwtSecurityToken, TokenValidationParameters )"/></para>
        /// <para><see cref="ValidateSigningToken( JwtSecurityToken )"/></para>
        /// <para><see cref="ValidateLifetime( JwtSecurityToken )"/>(</para>
        /// <para><see cref="ValidateAudience( JwtSecurityToken, TokenValidationParameters )"/>(</para>
        /// <para><see cref="ValidateIssuer( JwtSecurityToken, TokenValidationParameters )"/>(</para>
        /// </remarks>
        /// <exception cref="ArgumentNullException">'jwt' is null.</exception>
        /// <exception cref="ArgumentNullException">'validationParameters' is null.</exception>
        public virtual ClaimsPrincipal ValidateToken( JwtSecurityToken jwt, TokenValidationParameters validationParameters )
        {
            if ( jwt == null )
            {
                throw new ArgumentNullException( "jwt" );
            }

            if ( validationParameters == null )
            {
                throw new ArgumentNullException( "validationParameters" );
            }

            ValidateSignature( jwt, validationParameters );
            ValidateSigningToken( jwt );
            ValidateLifetime( jwt );
            ValidateAudience( jwt, validationParameters );
            return new ClaimsPrincipal( ClaimsIdentityFromJwt( jwt, ValidateIssuer( jwt, validationParameters ), validationParameters.SaveBootstrapContext ) );
        }

        /// <summary>
        /// Creates a <see cref="ClaimsIdentity"/> from a <see cref="JwtSecurityToken"/>.
        /// </summary>
        /// <param name="jwt">The <see cref="JwtSecurityToken"/> to use as a <see cref="Claim"/> source.</param>
        /// <param name="issuer">The value to set <see cref="Claim.Issuer"/></param>
        /// <param name="saveBootstrapContext">Flag indicating if the <see cref="JwtSecurityToken"/> should be attached to <see cref="ClaimsIdentity.BootstrapContext"/></param>
        /// <returns>A <see cref="ClaimsIdentity"/> containing the <see cref="JwtSecurityToken.Claims"/>.</returns>
        protected ClaimsIdentity ClaimsIdentityFromJwt( JwtSecurityToken jwt, string issuer, bool saveBootstrapContext )
        {
            ClaimsIdentity identity = new ClaimsIdentity( AuthenticationTypes.Federation, NameClaimType, RoleClaimType );

            if ( saveBootstrapContext )
            {
                if ( jwt.RawData != null )
                {
                    identity.BootstrapContext = new BootstrapContext( jwt.RawData );
                }
                else
                {
                    identity.BootstrapContext = new BootstrapContext( WriteToken( jwt ) );
                }
            }

            foreach ( Claim jwtClaim in jwt.Claims )
            {
                string claimType;
                bool wasMapped = false;
                if ( JwtSecurityTokenHandler.InboundClaimTypeMap.ContainsKey( jwtClaim.Type ) )
                {
                    claimType = JwtSecurityTokenHandler.InboundClaimTypeMap[jwtClaim.Type];
                    wasMapped = true;
                }
                else
                {
                    claimType = jwtClaim.Type;
                }

                if ( claimType == ClaimTypes.Actor )
                {
                    if ( identity.Actor != null )
                    {
                        throw new InvalidOperationException( string.Format( CultureInfo.InvariantCulture, JwtErrors.Jwt10401, JwtConstants.ReservedClaims.Actor, jwtClaim.Value ) );
                    }

                    if ( CanReadToken( jwtClaim.Value ) )
                    {
                        JwtSecurityToken actor = ReadToken( jwtClaim.Value ) as JwtSecurityToken;
                        identity.Actor = ClaimsIdentityFromJwt( actor, issuer, saveBootstrapContext );
                        if ( saveBootstrapContext )
                        {
                            identity.Actor.BootstrapContext = actor.RawData;
                        }
                    }
                    else
                    {
                        Claim claim = new Claim( claimType, jwtClaim.Value, jwtClaim.ValueType, issuer, issuer, identity );
                        if ( wasMapped )
                        {
                            claim.Properties.Add( ShortClaimTypeProperty, jwtClaim.Type );
                        }

                        identity.AddClaim( claim );
                    }
                }
                else
                {
                    Claim claim = new Claim( claimType, jwtClaim.Value, jwtClaim.ValueType, issuer, issuer, identity );
                    if ( wasMapped )
                    {
                        claim.Properties.Add( ShortClaimTypeProperty, jwtClaim.Type );
                    }

                    identity.AddClaim( claim );
                }
            }

            return identity;
        }

        /// <summary>
        /// Writes the <see cref="JwtSecurityToken"/> wrapped in a WS-Security BinarySecurityToken using the <see cref="XmlWriter"/>.
        /// </summary>
        /// <exception cref="ArgumentNullException">'writer' is null.</exception>
        /// <exception cref="ArgumentNullException">'token' is null.</exception>
        /// <exception cref="ArgumentException">'token' is not a not <see cref="JwtSecurityToken"/>.</exception>
        /// <remarks>The <see cref="JwtSecurityToken"/> current contents are encoded. If <see cref="JwtSecurityToken.SigningCredentials"/> is not null, the encoding will contain a signature.</remarks>
        public override void WriteToken( XmlWriter writer, SecurityToken token )
        {
            if ( writer == null )
            {
                throw new ArgumentNullException( "writer " );
            }

            if ( token == null )
            {
                throw new ArgumentNullException( "token " );
            }

            if ( !( token is JwtSecurityToken ) )
            {
                throw new ArgumentException( string.Format( CultureInfo.InvariantCulture, JwtErrors.Jwt10200, GetType(), typeof( JwtSecurityToken ), token.GetType() ) );
            }

            byte[] rawData = Encoding.UTF8.GetBytes( WriteToken( token ) );
            writer.WriteStartElement( WSSecurity10Constants.Prefix, WSSecurity10Constants.Elements.BinarySecurityToken, WSSecurity10Constants.Namespace );
            if ( token.Id != null )
            {
                writer.WriteAttributeString( WSSecurityUtilityConstants.Prefix, WSSecurityUtilityConstants.Attributes.Id, WSSecurityUtilityConstants.Namespace, token.Id );
            }

            writer.WriteAttributeString( WSSecurity10Constants.Attributes.ValueType, null, JwtConstants.TokenTypeAlt );
            writer.WriteAttributeString( WSSecurity10Constants.Attributes.EncodingType, null, WSSecurity10Constants.Base64EncodingType );
            writer.WriteBase64( rawData, 0, rawData.Length );
            writer.WriteEndElement();
        }

        /// <summary>
        /// Writes the <see cref="JwtSecurityToken"/> as a JSON Compact serialized format string.
        /// </summary>
        /// <param name="token"><see cref="JwtSecurityToken"/> to serialize.</param>
        /// <remarks>
        /// <para>If the <see cref="JwtSecurityToken.SigningCredentials"/> are not null, the encoding will contain a signature.</para>
        /// </remarks>
        /// <exception cref="ArgumentNullException">'token' is null.</exception>
        /// <exception cref="ArgumentException">'token' is not a not <see cref="JwtSecurityToken"/>.</exception>
        public override string WriteToken( SecurityToken token )
        {
            if ( token == null )
            {
                throw new ArgumentNullException( "token" );
            }

            JwtSecurityToken jwt = token as JwtSecurityToken;
            if ( jwt == null )
            {
                throw new ArgumentException( string.Format( CultureInfo.InvariantCulture, JwtErrors.Jwt10200, GetType(), typeof( JwtSecurityToken ), token.GetType() ) );
            }

            string signature    = string.Empty;           
            string signingInput = string.Concat( jwt.EncodedHeader, ".", jwt.EncodedPayload );

            if ( jwt.SigningCredentials != null )
            {
                signature = Base64UrlEncoder.Encode( CreateSignature( signingInput, jwt.SigningCredentials.SigningKey, jwt.SigningCredentials.SignatureAlgorithm ) );
            }

            return string.Concat( signingInput, ".", signature );
        }
    }
}