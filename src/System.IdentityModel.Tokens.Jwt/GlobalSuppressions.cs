﻿// This file is used by Code Analysis to maintain SuppressMessage
// attributes that are applied to this project.
// Project-level suppressions either have no target or are given
// a specific target and scoped to a namespace, type, member, etc.

using System.Diagnostics.CodeAnalysis;

[assembly: SuppressMessage("Usage", "CA2227:Collection properties should be read only", Justification = "Breaking change", Scope = "member", Target = "~P:System.IdentityModel.Tokens.Jwt.JwtSecurityTokenHandler.InboundClaimFilter")]
[assembly: SuppressMessage("Usage", "CA2227:Collection properties should be read only", Justification = "Breaking change", Scope = "member", Target = "~P:System.IdentityModel.Tokens.Jwt.JwtSecurityTokenHandler.OutboundClaimTypeMap")]
[assembly: SuppressMessage("Usage", "CA2227:Collection properties should be read only", Justification = "Breaking change", Scope = "member", Target = "~P:System.IdentityModel.Tokens.Jwt.JwtSecurityTokenHandler.InboundClaimTypeMap")]
[assembly: SuppressMessage("Usage", "CA2211:Non-constant fields should not be visible", Justification = "Breaking change", Scope = "member", Target = "~F:System.IdentityModel.Tokens.Jwt.JwtSecurityTokenHandler.DefaultInboundClaimTypeMap")]
[assembly: SuppressMessage("Usage", "CA2211:Non-constant fields should not be visible", Justification = "Breaking change", Scope = "member", Target = "~F:System.IdentityModel.Tokens.Jwt.JwtSecurityTokenHandler.DefaultMapInboundClaims")]
[assembly: SuppressMessage("Usage", "CA2211:Non-constant fields should not be visible", Justification = "Breaking change", Scope = "member", Target = "~F:System.IdentityModel.Tokens.Jwt.JwtSecurityTokenHandler.DefaultOutboundClaimTypeMap")]
[assembly: SuppressMessage("Usage", "CA2211:Non-constant fields should not be visible", Justification = "Breaking change", Scope = "member", Target = "~F:System.IdentityModel.Tokens.Jwt.JwtSecurityTokenHandler.DefaultInboundClaimFilter")]
[assembly: SuppressMessage("Usage", "CA2211:Non-constant fields should not be visible", Justification = "Breaking change", Scope = "member", Target = "~F:System.IdentityModel.Tokens.Jwt.JwtSecurityTokenHandler.DefaultOutboundAlgorithmMap")]
[assembly: SuppressMessage("Design", "CA1031:Do not catch general exception types", Justification = "Exception is written to a string", Scope = "member", Target = "~M:System.IdentityModel.Tokens.Jwt.JwtSecurityTokenHandler.DecryptToken(System.IdentityModel.Tokens.Jwt.JwtSecurityToken,Microsoft.IdentityModel.Tokens.TokenValidationParameters)~System.String")]
[assembly: SuppressMessage("Design", "CA1031:Do not catch general exception types", Justification = "Exception is written to a string", Scope = "member", Target = "~M:System.IdentityModel.Tokens.Jwt.JwtSecurityTokenHandler.ValidateSignature(System.String,Microsoft.IdentityModel.Tokens.TokenValidationParameters)~System.IdentityModel.Tokens.Jwt.JwtSecurityToken")]
[assembly: SuppressMessage("Design", "CA1054:Uri parameters should not be strings", Justification = "Breaking change", Scope = "member", Target = "~M:System.IdentityModel.Tokens.Jwt.JwtHeader.Base64UrlDeserialize(System.String)~System.IdentityModel.Tokens.Jwt.JwtHeader")]
[assembly: SuppressMessage("Design", "CA1055:Uri return values should not be strings", Justification = "Breaking change", Scope = "member", Target = "~M:System.IdentityModel.Tokens.Jwt.JwtHeader.Base64UrlEncode~System.String")]
[assembly: SuppressMessage("Performance", "CA1815:Override equals and operator equals on value types", Justification = "Holds no members", Scope = "type", Target = "~T:System.IdentityModel.Tokens.Jwt.JwtHeaderParameterNames")]
[assembly: SuppressMessage("Design", "CA1055:Uri return values should not be strings", Justification = "<Pending>", Scope = "member", Target = "~M:System.IdentityModel.Tokens.Jwt.JwtPayload.Base64UrlEncode~System.String")]
[assembly: SuppressMessage("Design", "CA1054:Uri parameters should not be strings", Justification = "<Pending>", Scope = "member", Target = "~M:System.IdentityModel.Tokens.Jwt.JwtPayload.Base64UrlDeserialize(System.String)~System.IdentityModel.Tokens.Jwt.JwtPayload")]
[assembly: SuppressMessage("Performance", "CA1815:Override equals and operator equals on value types", Justification = "Holds no members", Scope = "type", Target = "~T:System.IdentityModel.Tokens.Jwt.JwtRegisteredClaimNames")]
[assembly: SuppressMessage("Design", "CA1031:Do not catch general exception types", Justification = "Exception is written to a string", Scope = "member", Target = "~M:System.IdentityModel.Tokens.Jwt.JwtSecurityTokenHandler.GetContentEncryptionKeys(System.IdentityModel.Tokens.Jwt.JwtSecurityToken,Microsoft.IdentityModel.Tokens.TokenValidationParameters)~System.Collections.Generic.IEnumerable{Microsoft.IdentityModel.Tokens.SecurityKey}")]
[assembly: SuppressMessage("Design", "CA1031:Do not catch general exception types", Justification = "Exception is written to a string", Scope = "member", Target = "~M:System.IdentityModel.Tokens.Jwt.JwtSecurityTokenHandler.ValidateToken(System.String,Microsoft.IdentityModel.Tokens.TokenValidationParameters,Microsoft.IdentityModel.Tokens.SecurityToken@)~System.Security.Claims.ClaimsPrincipal")]
[assembly: SuppressMessage("Design", "CA1031:Do not catch general exception types", Justification = "Exception is written to a string.", Scope = "member", Target = "~M:System.IdentityModel.Tokens.Jwt.JwtSecurityTokenHandler.ValidateToken(System.String,System.IdentityModel.Tokens.Jwt.JwtSecurityToken,Microsoft.IdentityModel.Tokens.TokenValidationParameters,Microsoft.IdentityModel.Tokens.SecurityToken@)~System.Security.Claims.ClaimsPrincipal")]
[assembly: SuppressMessage("Design", "CA1031:Do not catch general exception types", Justification = "Exception is returned from the method.", Scope = "member", Target = "~M:System.IdentityModel.Tokens.Jwt.JwtSecurityTokenHandler.ValidateJWE(System.String,System.IdentityModel.Tokens.Jwt.JwtSecurityToken,Microsoft.IdentityModel.Tokens.TokenValidationParameters,Microsoft.IdentityModel.Tokens.BaseConfiguration,Microsoft.IdentityModel.Tokens.SecurityToken@,System.Runtime.ExceptionServices.ExceptionDispatchInfo@)~System.Security.Claims.ClaimsPrincipal")]
[assembly: SuppressMessage("Design", "CA1031:Do not catch general exception types", Justification = "Exception is returned from the method.", Scope = "member", Target = "~M:System.IdentityModel.Tokens.Jwt.JwtSecurityTokenHandler.ValidateJWS(System.String,Microsoft.IdentityModel.Tokens.TokenValidationParameters,Microsoft.IdentityModel.Tokens.BaseConfiguration,Microsoft.IdentityModel.Tokens.SecurityToken@,System.Runtime.ExceptionServices.ExceptionDispatchInfo@)~System.Security.Claims.ClaimsPrincipal")]
[assembly: SuppressMessage("Design", "CA1031:Do not catch general exception types", Justification = "Exception is returned from the method.", Scope = "member", Target = "~M:System.IdentityModel.Tokens.Jwt.JwtSecurityTokenHandler.ValidateTokenAsync(System.String,Microsoft.IdentityModel.Tokens.TokenValidationParameters)~System.Threading.Tasks.Task{Microsoft.IdentityModel.Tokens.TokenValidationResult}")]
[assembly: SuppressMessage("Globalization", "CA1307:Specify StringComparison", Justification = "Vendored component", Scope = "module")]
[assembly: SuppressMessage("Design", "CA1031:Do not catch general exception types", Justification = "Exception is written to a string", Scope = "member", Target = "~M:System.IdentityModel.Tokens.Jwt.JwtSecurityTokenHandler.ValidateSignature(System.String,System.IdentityModel.Tokens.Jwt.JwtSecurityToken,Microsoft.IdentityModel.Tokens.TokenValidationParameters,Microsoft.IdentityModel.Tokens.BaseConfiguration)~System.IdentityModel.Tokens.Jwt.JwtSecurityToken")]
[assembly: SuppressMessage("Usage", "VSTHRD002:Avoid problematic synchronous waits", Justification = "Cannot change the signature of the public method.", Scope = "member", Target = "~M:System.IdentityModel.Tokens.Jwt.JwtSecurityTokenHandler.ValidateToken(System.String,System.IdentityModel.Tokens.Jwt.JwtSecurityToken,Microsoft.IdentityModel.Tokens.TokenValidationParameters,Microsoft.IdentityModel.Tokens.SecurityToken@)~System.Security.Claims.ClaimsPrincipal")]
[assembly: SuppressMessage("ApiDesign", "RS0027:API with optional parameter(s) should have the most parameters amongst its public overloads", Justification = "Existing public API.", Scope = "member", Target = "~M:System.IdentityModel.Tokens.Jwt.JwtSecurityTokenHandler.CreateJwtSecurityToken(System.String,System.String,System.Security.Claims.ClaimsIdentity,System.Nullable{System.DateTime},System.Nullable{System.DateTime},System.Nullable{System.DateTime},Microsoft.IdentityModel.Tokens.SigningCredentials)~System.IdentityModel.Tokens.Jwt.JwtSecurityToken")]
[assembly: SuppressMessage("ApiDesign", "RS0027:API with optional parameter(s) should have the most parameters amongst its public overloads", Justification = "Existing public API.", Scope = "member", Target = "~M:System.IdentityModel.Tokens.Jwt.JwtSecurityToken.#ctor(System.String,System.String,System.Collections.Generic.IEnumerable{System.Security.Claims.Claim},System.Nullable{System.DateTime},System.Nullable{System.DateTime},Microsoft.IdentityModel.Tokens.SigningCredentials)")]
