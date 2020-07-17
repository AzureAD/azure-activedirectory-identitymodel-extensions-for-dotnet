// This file is used by Code Analysis to maintain SuppressMessage
// attributes that are applied to this project.
// Project-level suppressions either have no target or are given
// a specific target and scoped to a namespace, type, member, etc.

using System.Diagnostics.CodeAnalysis;

[assembly: SuppressMessage("Performance", "CA1819:Properties should not return arrays", Justification = "<Pending>", Scope = "member", Target = "~P:Microsoft.IdentityModel.Protocols.WsTrust.ProtectedKey.Secret")]
[assembly: SuppressMessage("", "CA1062:Validate arguments of public methods", Justification = "validation is performed in WsUtils.CheckReaderOnEntry", Scope = "member", Target = "~M:Microsoft.IdentityModel.Protocols.WsTrust.WsTrustSerializer.ReadRequest(System.Xml.XmlDictionaryReader)~Microsoft.IdentityModel.Protocols.WsTrust.WsTrustRequest")]
[assembly: SuppressMessage("Design", "CA1062:Validate arguments of public methods", Justification = "validation is performed in WsUtils.CheckReaderOnEntry", Scope = "member", Target = "~M:Microsoft.IdentityModel.Protocols.WsTrust.WsTrustSerializer.ReadResponse(System.Xml.XmlDictionaryReader)~Microsoft.IdentityModel.Protocols.WsTrust.WsTrustResponse")]
[assembly: SuppressMessage("Design", "CA1056:Uri properties should not be strings", Justification = "<Pending>", Scope = "member", Target = "~P:Microsoft.IdentityModel.Protocols.WsFed.ClaimType.Uri")]
[assembly: SuppressMessage("Usage", "CA2211:Non-constant fields should not be visible", Justification = "Type has no properties", Scope = "member", Target = "~F:Microsoft.IdentityModel.Protocols.WsTrust.WsTrustVersion.TrustFeb2005")]
[assembly: SuppressMessage("Usage", "CA2211:Non-constant fields should not be visible", Justification = "Type has no properties", Scope = "member", Target = "~F:Microsoft.IdentityModel.Protocols.WsTrust.WsTrustVersion.Trust14")]
[assembly: SuppressMessage("Usage", "CA2211:Non-constant fields should not be visible", Justification = "Type has no properties", Scope = "member", Target = "~F:Microsoft.IdentityModel.Protocols.WsTrust.WsTrustVersion.Trust13")]
[assembly: SuppressMessage("Usage", "CA2211:Non-constant fields should not be visible", Justification = "Type has no properties", Scope = "member", Target = "~F:Microsoft.IdentityModel.Protocols.WsAddressing.WsAddressingVersion.Addressing10")]
[assembly: SuppressMessage("Usage", "CA2211:Non-constant fields should not be visible", Justification = "Type has no properties", Scope = "member", Target = "~F:Microsoft.IdentityModel.Protocols.WsSecurity.WsSecurityVersion.Security10")]
[assembly: SuppressMessage("Usage", "CA2211:Non-constant fields should not be visible", Justification = "Type has no properties", Scope = "member", Target = "~F:Microsoft.IdentityModel.Protocols.WsSecurity.WsSecurityVersion.Security11")]
[assembly: SuppressMessage("Usage", "CA2211:Non-constant fields should not be visible", Justification = "Type has no properties", Scope = "member", Target = "~F:Microsoft.IdentityModel.Protocols.WsFed.WsFedVersion.Fed12")]
[assembly: SuppressMessage("Usage", "CA2211:Non-constant fields should not be visible", Justification = "Type has no properties", Scope = "member", Target = "~F:Microsoft.IdentityModel.Protocols.WsPolicy.WsPolicyVersion.Policy12")]
[assembly: SuppressMessage("Usage", "CA2211:Non-constant fields should not be visible", Justification = "Type has no properties", Scope = "member", Target = "~F:Microsoft.IdentityModel.Protocols.WsPolicy.WsPolicyVersion.Policy15")]
[assembly: SuppressMessage("Usage", "CA2211:Non-constant fields should not be visible", Justification = "Type has no properties", Scope = "member", Target = "~F:Microsoft.IdentityModel.Protocols.WsAddressing.WsAddressingVersion.Addressing200408")]
[assembly: SuppressMessage("Performance", "CA1819:Properties should not return arrays", Justification = "Copy of array is returned", Scope = "member", Target = "~P:Microsoft.IdentityModel.Protocols.WsTrust.BinaryExchange.BinaryData")]
[assembly: SuppressMessage("Performance", "CA1819:Properties should not return arrays", Justification = "Copy of array is returned", Scope = "member", Target = "~P:Microsoft.IdentityModel.Protocols.WsTrust.BinarySecret.Data")]
//[assembly: SuppressMessage("Performance", "CA1822:Mark members as static", Justification = "<Pending>", Scope = "member", Target = "~M:Microsoft.IdentityModel.Protocols.WsTrust.WsTrustSerializer.WriteRequestedProofToken(System.Xml.XmlDictionaryWriter,Microsoft.IdentityModel.Protocols.WsSerializationContext,Microsoft.IdentityModel.Protocols.WsTrust.RequestedProofToken)")]
[assembly: SuppressMessage("Design", "CA1724:Properties should not return arrays", Justification = "Copy of array is returned", Scope = "member", Target = "~P:Microsoft.IdentityModel.Protocols.WsTrust.BinarySecret.Data")]
[assembly: SuppressMessage("Design", "CA1056:Uri properties should not be strings", Justification = "<Pending>", Scope = "member", Target = "~P:Microsoft.IdentityModel.Protocols.WsPolicy.PolicyReference.Uri")]
[assembly: SuppressMessage("Design", "CA1054:Uri parameters should not be strings", Justification = "<Pending>", Scope = "member", Target = "~M:Microsoft.IdentityModel.Protocols.WsAddressing.EndpointReference.#ctor(System.String)")]
[assembly: SuppressMessage("Design", "CA1054:Uri parameters should not be strings", Justification = "<Pending>", Scope = "member", Target = "~M:Microsoft.IdentityModel.Protocols.WsPolicy.PolicyReference.#ctor(System.String,System.String,System.String)")]
[assembly: SuppressMessage("Microsoft.Naming", "CA1724:TypeNamesShouldNotMatchNamespaces", Justification = "Using same name as in spec", Scope = "type", Target = "~T:Microsoft.IdentityModel.Protocols.WsTrust.Lifetime")]
[assembly: SuppressMessage("Microsoft.Naming", "CA1724:TypeNamesShouldNotMatchNamespaces", Justification = "Using same name as in spec", Scope = "type", Target = "~T:Microsoft.IdentityModel.Protocols.WsTrust.Claims")]
[assembly: SuppressMessage("Design", "CA1056:Uri properties should not be strings", Justification = "<Pending>", Scope = "member", Target = "~P:Microsoft.IdentityModel.Protocols.WsAddressing.EndpointReference.Uri")]
