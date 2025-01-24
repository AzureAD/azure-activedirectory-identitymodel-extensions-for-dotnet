// This file is used by Code Analysis to maintain SuppressMessage
// attributes that are applied to this project.
// Project-level suppressions either have no target or are given
// a specific target and scoped to a namespace, type, member, etc.

using System.Diagnostics.CodeAnalysis;

[assembly: SuppressMessage("Design", "CA1055:Uri return values should not be strings", Justification = "Previously released as returning a string", Scope = "member", Target = "~M:Microsoft.IdentityModel.Protocols.AuthenticationProtocolMessage.BuildRedirectUrl~System.String")]
[assembly: SuppressMessage("Performance", "CA1819:Properties should not return arrays", Justification = "Previously released as returning an array", Scope = "member", Target = "~P:Microsoft.IdentityModel.Protocols.HttpRequestData.Body")]
[assembly: SuppressMessage("Usage", "CA2227:Collection properties should be read only", Justification = "Previously released read/write", Scope = "member", Target = "~P:Microsoft.IdentityModel.Protocols.HttpRequestData.Headers")]
[assembly: SuppressMessage("Usage", "CA2227:Collection properties should be read only", Justification = "Previously released read/write", Scope = "member", Target = "~P:Microsoft.IdentityModel.Protocols.HttpRequestData.PropertyBag")]
#if NET6_0_OR_GREATER
[assembly: SuppressMessage("Globalization", "CA1307:Specify StringComparison", Justification = "Adding StringComparison.Ordinal adds a performance penalty.", Scope = "member", Target = "~M:Microsoft.IdentityModel.Protocols.AuthenticationProtocolMessage.BuildRedirectUrl~System.String")]
#endif

[assembly: System.Diagnostics.CodeAnalysis.SuppressMessage(
    "Microsoft.Design",
    "CA1031:DoNotCatchGeneralExceptionTypes",
    Justification = "Exception handling is required for telemetry logging and to ensure the state is reset.",
    Scope = "member",
    Target = "~M:Microsoft.IdentityModel.Protocols.ConfigurationManager`1.ManualOrAutomaticConfigurationRefresh")]

[assembly: System.Diagnostics.CodeAnalysis.SuppressMessage(
    "Microsoft.Design",
    "CA1031:DoNotCatchGeneralExceptionTypes",
    Justification = "Ensure _configurationNullLock is reset.",
    Scope = "member",
    Target = "~M:Microsoft.IdentityModel.Protocols.ConfigurationManager`1.FirstFetchAsync(System.Threading.CancellationToken)~System.Threading.Tasks.Task{System.ValueTuple{`0,System.Exception}}")]

[assembly: System.Diagnostics.CodeAnalysis.SuppressMessage(
       "Microsoft.Design",
       "CA1031:DoNotCatchGeneralExceptionTypes",
       Justification = "Exception handling is required for telemetry logging and to ensure the state is reset.",
       Scope = "member",
       Target = "~M:Microsoft.IdentityModel.Protocols.ConfigurationManager`1.UpdateCurrentConfiguration")]
