using Microsoft.CodeAnalysis;
using Microsoft.CodeAnalysis.CSharp;
using Microsoft.CodeAnalysis.CSharp.Syntax;
using Microsoft.CodeAnalysis.Diagnostics;
using System;
using System.Collections.Generic;
using System.Collections.Immutable;
using System.Diagnostics;
using System.Linq;
using System.Text;
using System.Threading;

namespace Microsoft.Identity.VersionMatchAnalyzer
{
    [DiagnosticAnalyzer(LanguageNames.CSharp)]
    public class MicrosoftIdentityVersionMatchAnalyzerAnalyzer : DiagnosticAnalyzer
    {
        public const string DiagnosticId = "IdentityVersionMatchAnalyzer";
        public readonly List<string> WilsonAssemblyNames = new List<string>()
        {
            "Microsoft.IdentityModel.JsonWebTokens",
            "Microsoft.IdentityModel.KeyVaultExtensions",
            "Microsoft.IdentityModel.Logging",
            "Microsoft.IdentityModel.ManagedKeyVaultSecurityKey",
            "Microsoft.IdentityModel.Protocols.OpenIdConnect",
            "Microsoft.IdentityModel.Protocols.SignedHttpRequest",
            "Microsoft.IdentityModel.Protocols.WsFederation",
            "Microsoft.IdentityModel.Protocols",
            "Microsoft.IdentityModel.TestExtensions",
            "Microsoft.IdentityModel.Tokens.Saml",
            "Microsoft.IdentityModel.Tokens",
            "Microsoft.IdentityModel.Validators",
            "Microsoft.IdentityModel.Xml",
            "System.IdentityModel.Tokens.Jwt"
            // TODO: add older wilson assembly names as well
        };
        public readonly List<string> SalAssemblyNames = new List<string>()
        {
            "Microsoft.IdentityModel.S2S",
            "Microsoft.IdentityModel.S2S.Configuration",
            "Microsoft.IdentityModel.S2S.Extensions.AspNetCore",
            "Microsoft.IdentityModel.S2S.Extensions.Owin",
            "Microsoft.IdentityModel.S2S.Tokens.SealExtensions",
            "Microsoft.IdentityModel.S2S.SubstrateExtensions",
            "Microsoft.IdentityModel.S2S.Tokens"
        };

        private static DiagnosticDescriptor VersionMismatch { get; } =
       new DiagnosticDescriptor(
           DiagnosticId,
           "Version mismatch detected among these references. They all need to be of same version",
           "In project '{0}', Version mismatch detected among these references. They all need to be of same version {1}",
           category: "Maintainability",
           defaultSeverity: DiagnosticSeverity.Warning,
           isEnabledByDefault: true);

        public override ImmutableArray<DiagnosticDescriptor> SupportedDiagnostics { get { return ImmutableArray.Create(VersionMismatch); } }

        public override void Initialize(AnalysisContext context)
        {

            context.ConfigureGeneratedCodeAnalysis(GeneratedCodeAnalysisFlags.None);
            context.EnableConcurrentExecution();

            context.RegisterCompilationAction(ctxt =>
            {
                //Debugger.Launch();
                var compilation = ctxt.Compilation;
                var assemblies = compilation.ReferencedAssemblyNames;
                var foundWilsonAssemblies = new List<AssemblyIdentity>();
                var foundSalAssemblies = new List<AssemblyIdentity>();
                var wilsonMessage = new StringBuilder();
                var salMessage = new StringBuilder();

                foreach (var assembly in assemblies)
                {
                    if (WilsonAssemblyNames.Contains(assembly.Name, StringComparer.OrdinalIgnoreCase))
                    {
                        wilsonMessage.Append(assembly.Name + ":" + assembly.Version);
                        wilsonMessage.Append(";");
                        foundWilsonAssemblies.Add(assembly);
                    }

                    if (SalAssemblyNames.Contains(assembly.Name, StringComparer.OrdinalIgnoreCase))
                    {
                        salMessage.Append(assembly.Name + ":" + assembly.Version);
                        salMessage.Append(";");
                        foundSalAssemblies.Add(assembly);
                    }
                }

                if (DetectVersionMismatch(foundWilsonAssemblies))
                    ctxt.ReportDiagnostic(
                            Diagnostic.Create(
                                VersionMismatch,
                                null,
                                compilation.AssemblyName,
                                wilsonMessage
                                ));

                if (DetectVersionMismatch(foundSalAssemblies))
                    ctxt.ReportDiagnostic(
                            Diagnostic.Create(
                                VersionMismatch,
                                null,
                                compilation.AssemblyName,
                                salMessage
                                ));

                return;
            });
        }

        private bool DetectVersionMismatch(List<AssemblyIdentity> assemblies)
        {
            var version = assemblies.Any() ? assemblies.First().Version : null;

            if (version != null)
            {
                if (!assemblies.All(x => x.Version == version))
                    return true;
            }

            return false;
        }
    }
}
