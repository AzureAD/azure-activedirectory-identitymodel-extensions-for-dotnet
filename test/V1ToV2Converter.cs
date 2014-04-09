//------------------------------------------------------------
// Copyright (c) Microsoft Corporation.  All rights reserved.
//------------------------------------------------------------

using Microsoft.IdentityModel.Claims;
using Microsoft.IdentityModel.S2S.Tokens;
using System.Collections.Generic;
using AuthenticationInformation = System.Security.Claims.AuthenticationInformation;
using Claim = System.Security.Claims.Claim;
using ClaimsIdentity = System.Security.Claims.ClaimsIdentity;
using ClaimsPrincipal = System.Security.Claims.ClaimsPrincipal;
using SecurityTokenDescriptor = System.IdentityModel.Tokens.SecurityTokenDescriptor;
using v1AuthenticationInformation = Microsoft.IdentityModel.Claims.AuthenticationInformation;
using v1Claim = Microsoft.IdentityModel.Claims.Claim;
using v1ClaimsIdentity = Microsoft.IdentityModel.Claims.ClaimsIdentity;
using v1ClaimsPrincipal = Microsoft.IdentityModel.Claims.ClaimsPrincipal;
using v1SecurityTokenDescriptor = Microsoft.IdentityModel.Tokens.SecurityTokenDescriptor;

namespace System.IdentityModel.Test
{
    public static class V1ToV2Converter
    {

        static public v1AuthenticationInformation Convert( AuthenticationInformation authenticationInformation )
        {
            v1AuthenticationInformation v1AuthenticationInformation = new v1AuthenticationInformation();
            v1AuthenticationInformation.Address = authenticationInformation.Address;            
            // skipped - v1AuthenticationInformation.AuthorizationContexts;
            v1AuthenticationInformation.DnsName = authenticationInformation.DnsName;
            v1AuthenticationInformation.NotOnOrAfter = authenticationInformation.NotOnOrAfter;
            v1AuthenticationInformation.Session = authenticationInformation.Session;

            return v1AuthenticationInformation;
        }

        static public IEnumerable<JsonWebTokenClaim> ConvertToJwC( IEnumerable<Claim> claims )
        {
            foreach ( Claim c in claims )
            {
                yield return new JsonWebTokenClaim( c.Type, c.Value );
            }
        }

        static public IEnumerable<Claim> Convert( ClaimCollection claims )
        {
            foreach ( v1Claim claim in claims )
            {
                yield return new Claim( claim.ClaimType, claim.Value, claim.ValueType, claim.Issuer, claim.OriginalIssuer );
            }
        }

        static public IEnumerable<v1Claim> Convert( IEnumerable<Claim> claims )
        {
            foreach ( Claim claim in claims )
            {
                yield return new v1Claim( claim.Type, claim.Value, claim.ValueType, claim.Issuer, claim.OriginalIssuer );
            }
        }

        static public v1ClaimsIdentity Convert( ClaimsIdentity claimsIdentity )
        {
            v1ClaimsIdentity v1ClaimsIdentity = new v1ClaimsIdentity();

            foreach ( Claim claim in claimsIdentity.Claims )
            {
                v1ClaimsIdentity.Claims.Add( new v1Claim( claim.Type, claim.Value, claim.ValueType, claim.Issuer, claim.OriginalIssuer ) );
            }

            return v1ClaimsIdentity;
        }

        static public ClaimsIdentity Convert( v1ClaimsIdentity v1ClaimsIdentity )
        {
            ClaimsIdentity claimsIdentity = new ClaimsIdentity();

            foreach ( v1Claim v1claim in v1ClaimsIdentity.Claims )
            {
                claimsIdentity.AddClaim( new Claim( v1claim.ClaimType, v1claim.Value, v1claim.ValueType, v1claim.Issuer, v1claim.OriginalIssuer ) );
            }

            return claimsIdentity;
        }

        static public ClaimsPrincipal Convert( v1ClaimsPrincipal v1ClaimsPrincipal )
        {
            ClaimsPrincipal claimsPrincipal = new ClaimsPrincipal();
            foreach ( v1ClaimsIdentity v1claimsIdentity in v1ClaimsPrincipal.Identities )
            {
                claimsPrincipal.AddIdentity( Convert( v1claimsIdentity ) );
            }

            return claimsPrincipal;
        }

        public static Microsoft.IdentityModel.Tokens.SecurityTokenDescriptor Convert( SecurityTokenDescriptor tokenDescriptor )
        {
            v1SecurityTokenDescriptor v1TokenDescriptor = new v1SecurityTokenDescriptor();

            if ( tokenDescriptor.AppliesToAddress != null )
                v1TokenDescriptor.AppliesToAddress = tokenDescriptor.AppliesToAddress;

            if ( tokenDescriptor.AttachedReference != null )
                v1TokenDescriptor.AttachedReference = tokenDescriptor.AttachedReference;

            if ( tokenDescriptor.AuthenticationInfo != null )
                v1TokenDescriptor.AuthenticationInfo = Convert(tokenDescriptor.AuthenticationInfo);

            if ( tokenDescriptor.Lifetime != null )
                v1TokenDescriptor.Lifetime = new Microsoft.IdentityModel.Protocols.WSTrust.Lifetime( tokenDescriptor.Lifetime.Created, tokenDescriptor.Lifetime.Expires );

            if ( tokenDescriptor.ReplyToAddress != null )
                v1TokenDescriptor.ReplyToAddress = tokenDescriptor.ReplyToAddress;

            if ( tokenDescriptor.SigningCredentials != null )
                v1TokenDescriptor.SigningCredentials = tokenDescriptor.SigningCredentials;

            if ( tokenDescriptor.Subject != null )
                v1TokenDescriptor.Subject = Convert( tokenDescriptor.Subject );

            if ( tokenDescriptor.TokenIssuerName != null )
                v1TokenDescriptor.TokenIssuerName = tokenDescriptor.TokenIssuerName;

            if ( tokenDescriptor.TokenType != null )
                v1TokenDescriptor.TokenType = tokenDescriptor.TokenType;

            return v1TokenDescriptor;
        }
    }
}
