// ----------------------------------------------------------------------------------
//
// Copyright Microsoft Corporation
// Licensed under the Apache License, Version 2.0 (the "License");
// you may not use this file except in compliance with the License.
// You may obtain a copy of the License at
// http://www.apache.org/licenses/LICENSE-2.0
// Unless required by applicable law or agreed to in writing, software
// distributed under the License is distributed on an "AS IS" BASIS,
// WITHOUT WARRANTIES OR CONDITIONS OF ANY KIND, either express or implied.
// See the License for the specific language governing permissions and
// limitations under the License.
// ----------------------------------------------------------------------------------

using Microsoft.VisualStudio.TestTools.UnitTesting;
using System.Collections.Generic;
using System.IdentityModel.Protocols.WSTrust;
using System.IdentityModel.Selectors;
using System.IdentityModel.Tokens;
using System.Reflection;
using System.Security.Claims;
using System.Text;
using System.Xml;

namespace System.IdentityModel.Test
{
    /// <summary>
    /// This class is used to define the construction of a JWT for testing purposes.
    /// Use it by writing a method to populate a set for a specific purpose, such as SignatureValidationVariations, below.
    /// Then run through a loop that checks expected results.
    /// 
    /// </summary>
    public class JwtSecurityTokenTestVariation
    {
        // it is helpful to have these as a defaults
        DateTime _validFrom;
        DateTime _validTo;        
        JwtSecurityTokenHandler _jwtHandler;
        ExpectedException _expectedException;

        public JwtSecurityTokenTestVariation() 
        {
            _validFrom = DateTime.UtcNow;
            _validTo = DateTime.UtcNow + TimeSpan.FromHours( 1 );
            _jwtHandler = new JwtSecurityTokenHandler();
            _expectedException = ExpectedException.Null;
        }
        // ===========================
        // token setup params - different variations will set different items

        public JwtSecurityToken Actor { get; set; }
        public string Audience { get; set; }
        public bool BoolRetVal { get; set; }
        public X509CertificateValidator CertificateValidator { get; set; }
        public IEnumerable<Claim> Claims { get; set; }
        public ClaimsPrincipal ClaimsPrincipal { get; set; }
        public UInt32 DefaultTokenLifetimeInMinutes { get; set; }
        public SecurityKeyIdentifierClause SecurityKeyIdentifierClause { get; set; }
        public string EncodedString { get; set; }
        public IList<Exception> Exceptions { get; set; }
        public ExpectedException ExpectedException { get { return _expectedException; } set { _expectedException = value; } }
        public JwtSecurityToken ExpectedJwtSecurityToken { get; set; }
        public string Issuer { get; set; }
        public JwtSecurityTokenHandler JwtSecurityTokenHandler { get { return _jwtHandler; } set { _jwtHandler = value; } }
        public JwtSecurityToken JwtSecurityToken { get; set; }
        public JwtSecurityTokenRequirement JwtSecurityTokenRequirement { get; set; }
        public Lifetime Lifetime { get; set; }
        public string Name { get; set; }
        public string NameClaimType { get; set; }
        public TimeSpan MaxClockSkew { get; set; }
        public UInt32 MaxTokenSizeInBytes { get; set; }
        public string OriginalIssuer { get; set; }
        public bool RequireExpirationTime { get; set; }
        public bool RequireSignedTokens { get; set; }
        public string RoleClaimType { get; set; }
        public SecurityToken SecurityToken { get; set; }
        public SecurityTokenDescriptor SecurityTokenDescriptor { get; set; }
        public byte[] Signature { get; set; }
        public SignatureProviderFactory SignatureProviderFactory { get; set; }
        public SigningCredentials SigningCredentials { get; set; }
        public string SigningInput { get; set; }
        public SecurityToken SigningToken { get; set; }
        public Type TokenType { get; set; }
        public string[] TokenTypeIdentifiers { get; set; }
        public TokenValidationParameters TokenValidationParameters { get; set; }
        public byte[] UnsignedBytes { get; set; }
        public DateTime ValidFrom { get { return _validFrom; } set { _validFrom = value; } }
        public DateTime ValidTo { get { return _validTo; } set { _validTo = value; } }
        public XmlNodeList XmlNodeList { get; set; }
        public XmlReader XmlReader { get; set; }
        public XmlWriter XmlWriter { get; set; }
    }

    public class JwtTestUtilities
    {
        public static TokenValidationParameters SignatureValidationParameters( SecurityToken signingToken = null, List<SecurityToken> signingTokens = null )
        {
            return new TokenValidationParameters()
            {
                AudienceUriMode = AudienceUriMode.Never,
                SigningToken = signingToken,
                SigningTokens = signingTokens,
                ValidIssuer = "http://GotJwt.com",
            };
        }

        public static string GetJwtParts( string jwt, string whichParts )
        {
            string[] parts = jwt.Split( '.' );
            if ( string.Equals( whichParts, "AllParts", StringComparison.OrdinalIgnoreCase ) )
            {
                return string.Format( "{0}.{1}.{2}", parts[0], parts[1], parts[2] );
            }
            
            if ( string.Equals( whichParts, "Parts-0-1", StringComparison.OrdinalIgnoreCase ) )
            {
                return string.Format( "{0}.{1}.", parts[0], parts[1] );
            }

            Console.WriteLine( string.Format("Hey, the 'whichParts' parameter wasn't recognized: '{0}'.  Returning'string.Empty' hope that is what you wanted", whichParts ) );

            return string.Empty;
        }

        /// <summary>
        /// Calls all public instance and static properties on an object
        /// </summary>
        /// <param name="obj"></param>
        /// <param name="testcase">contains info about the current test case</param>
        public static void CallAllPublicInstanceAndStaticPropertyGets( object obj, string testcase )
        {
            if ( obj == null )
            {
                Console.WriteLine( string.Format( "Entering: '{0}', obj is null, have to return.  Is the Testcase: '{1}' right?", MethodBase.GetCurrentMethod(), testcase ?? "testcase is null" ) );
                return;
            }

            Type type = obj.GetType();
            Console.WriteLine( string.Format( "Testcase: '{0}', type: '{1}', Method: '{2}'.", testcase ?? "testcase is null", type, MethodBase.GetCurrentMethod() ) );

            // call get all public static properties of MyClass type

            PropertyInfo[] propertyInfos = type.GetProperties( BindingFlags.Public | BindingFlags.Instance | BindingFlags.Static );

            // Touch each public property
            foreach ( PropertyInfo propertyInfo in propertyInfos )
            {
                try
                {
                    if ( propertyInfo.GetMethod != null )
                    {
                        object retval = propertyInfo.GetValue( obj, null );
                    }
                }
                catch ( Exception ex )
                {
                    Assert.Fail( string.Format( "Testcase: '{0}', type: '{1}', property: '{2}', exception: '{3}'", type, testcase ?? "testcase is null", propertyInfo.Name, ex ) );
                }
            }
        }

        public static string SerializeAsSingleCommaDelimitedString( IEnumerable<string> strings )
        {
            if ( null == strings )
            {
                return "null";
            }

            StringBuilder sb = new StringBuilder();
            bool first = true;
            foreach ( string str in strings )
            {

                if ( first )
                {
                    sb.AppendFormat( "{0}", str ?? "null" );
                    first = false;
                }
                else
                {
                    sb.AppendFormat( ", {0}", str ?? "null" );
                }
            }

            if ( first )
            {
                return "empty";
            }

            return sb.ToString();
        }
    }
}
