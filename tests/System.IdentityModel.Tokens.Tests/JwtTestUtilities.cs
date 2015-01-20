//-----------------------------------------------------------------------
// Copyright (c) Microsoft Open Technologies, Inc.
// All Rights Reserved
// Apache License 2.0
//
// Licensed under the Apache License, Version 2.0 (the "License");
// you may not use this file except in compliance with the License.
// You may obtain a copy of the License at
// 
// http://www.apache.org/licenses/LICENSE-2.0
// 
// Unless required by applicable law or agreed to in writing, software
// distributed under the License is distributed on an "AS IS" BASIS,
// WITHOUT WARRANTIES OR CONDITIONS OF ANY KIND, either express or implied.
// See the License for the specific language governing permissions and
// limitations under the License.
//-----------------------------------------------------------------------

using System.Collections.Generic;
using System.IdentityModel.Tokens;
using System.Security.Claims;
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
        DateTime _notbefore;
        DateTime _expires;        
        JwtSecurityTokenHandler _jwtHandler;
        ExpectedException _expectedException;

        public JwtSecurityTokenTestVariation() 
        {
            _notbefore = DateTime.UtcNow;
            _expires = DateTime.UtcNow + TimeSpan.FromHours( 1 );
            _jwtHandler = new JwtSecurityTokenHandler();
            _expectedException = ExpectedException.NoExceptionExpected;
        }
        // ===========================
        // token setup params - different variations will set different items

        public JwtSecurityToken Actor { get; set; }
        public string Audience { get; set; }
        public bool BoolRetVal { get; set; }
        public IEnumerable<Claim> Claims { get; set; }
        public ClaimsPrincipal ClaimsPrincipal { get; set; }
        public uint DefaultTokenLifetimeInMinutes { get; set; }
        public string EncodedString { get; set; }
        public IList<Exception> Exceptions { get; set; }
        public ExpectedException ExpectedException { get { return _expectedException; } set { _expectedException = value; } }
        public JwtSecurityToken ExpectedJwtSecurityToken { get; set; }
        public string Issuer { get; set; }
        public JwtSecurityTokenHandler JwtSecurityTokenHandler { get { return _jwtHandler; } set { _jwtHandler = value; } }
        public JwtSecurityToken JwtSecurityToken { get; set; }
        public string Name { get; set; }
        public string NameClaimType { get; set; }
        public TimeSpan MaxClockSkew { get; set; }
        public uint MaxTokenSizeInBytes { get; set; }
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
        public DateTime NotBefore { get { return _notbefore; } set { _notbefore = value; } }
        public DateTime Expires { get { return _expires; } set { _expires = value; } }
        public XmlReader XmlReader { get; set; }
        public XmlWriter XmlWriter { get; set; }
    }

    public class JwtTestUtilities
    {

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

    }
}
