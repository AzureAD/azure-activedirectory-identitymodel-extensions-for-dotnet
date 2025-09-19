// Copyright (c) Microsoft Corporation. All rights reserved.
// Licensed under the MIT License.

using System;
using System.Collections.Generic;
using System.Collections.Immutable;
using System.Linq;
using System.Threading;
using Microsoft.CodeAnalysis;
using Microsoft.CodeAnalysis.CSharp;
using Microsoft.CodeAnalysis.CSharp.Syntax;
using Microsoft.CodeAnalysis.Diagnostics;

namespace Microsoft.IdentityModel.Analyzers
{
    [DiagnosticAnalyzer(LanguageNames.CSharp)]
    public class MicrosoftIdentityModelAnalyzer : DiagnosticAnalyzer
    {
        #region DiagnosticDescriptors
        public const string DiagnosticId1 = "IDMODEL101";
        public const string DiagnosticId2 = "IDMODEL102";
        public const string DiagnosticId3 = "IDMODEL103";
        public const string DiagnosticId4 = "IDMODEL104";
        public const string DiagnosticId5 = "IDMODEL105";

        // You can change these strings in the Resources.resx file. If you do not want your analyzer to be localize-able, you can use regular strings for Title and MessageFormat.
        // See https://github.com/dotnet/roslyn/blob/main/docs/analyzers/Localizing%20Analyzers.md for more on localization
        private static readonly LocalizableString Title1 = new LocalizableResourceString(nameof(Resources.AnalyzerTitle1), Resources.ResourceManager, typeof(Resources));
        private static readonly LocalizableString MessageFormat1 = new LocalizableResourceString(nameof(Resources.AnalyzerMessageFormat1), Resources.ResourceManager, typeof(Resources));
        private static readonly LocalizableString Description1 = new LocalizableResourceString(nameof(Resources.AnalyzerDescription1), Resources.ResourceManager, typeof(Resources));
        private const string Category1 = "Naming";

        private static readonly DiagnosticDescriptor Rule1 = new DiagnosticDescriptor(DiagnosticId1, Title1, MessageFormat1, Category1, DiagnosticSeverity.Warning, isEnabledByDefault: true, description: Description1);

        private static readonly LocalizableString Title2 = new LocalizableResourceString(nameof(Resources.AnalyzerTitle2), Resources.ResourceManager, typeof(Resources));
        private static readonly LocalizableString MessageFormat2 = new LocalizableResourceString(nameof(Resources.AnalyzerMessageFormat2), Resources.ResourceManager, typeof(Resources));
        private static readonly LocalizableString Description2 = new LocalizableResourceString(nameof(Resources.AnalyzerDescription2), Resources.ResourceManager, typeof(Resources));
        private const string Category2 = "Format";

        private static readonly DiagnosticDescriptor Rule2 = new DiagnosticDescriptor(DiagnosticId2, Title2, MessageFormat2, Category2, DiagnosticSeverity.Warning, isEnabledByDefault: true, description: Description2);

        private static readonly LocalizableString Title3 = new LocalizableResourceString(nameof(Resources.AnalyzerTitle3), Resources.ResourceManager, typeof(Resources));
        private static readonly LocalizableString MessageFormat3 = new LocalizableResourceString(nameof(Resources.AnalyzerMessageFormat3), Resources.ResourceManager, typeof(Resources));
        private static readonly LocalizableString Description3 = new LocalizableResourceString(nameof(Resources.AnalyzerDescription3), Resources.ResourceManager, typeof(Resources));
        private const string Category3 = "Usage";

        private static readonly DiagnosticDescriptor Rule3 = new DiagnosticDescriptor(DiagnosticId3, Title3, MessageFormat3, Category3, DiagnosticSeverity.Error, isEnabledByDefault: true, description: Description3);

        private static readonly LocalizableString Title4 = new LocalizableResourceString(nameof(Resources.AnalyzerTitle4), Resources.ResourceManager, typeof(Resources));
        private static readonly LocalizableString MessageFormat4 = new LocalizableResourceString(nameof(Resources.AnalyzerMessageFormat4), Resources.ResourceManager, typeof(Resources));
        private static readonly LocalizableString Description4 = new LocalizableResourceString(nameof(Resources.AnalyzerDescription4), Resources.ResourceManager, typeof(Resources));
        private const string Category4 = "Dependency Versioning";

        private static readonly DiagnosticDescriptor Rule4 = new DiagnosticDescriptor(DiagnosticId4, Title4, MessageFormat4, Category4, DiagnosticSeverity.Error, isEnabledByDefault: true, description: Description4);
        #endregion
        public override ImmutableArray<DiagnosticDescriptor> SupportedDiagnostics { get { return ImmutableArray.Create(Rule1, Rule2, Rule3, Rule4); } }

        public override void Initialize(AnalysisContext context)
        {
            context.ConfigureGeneratedCodeAnalysis(GeneratedCodeAnalysisFlags.None);
            context.EnableConcurrentExecution();

            context.RegisterSymbolAction(AnalyzeTypeCasing, SymbolKind.NamedType);
            context.RegisterSyntaxTreeAction(AnalyzeNestedStatements);
            context.RegisterSyntaxNodeAction(AnalyzeJsonWebTokenCreation, SyntaxKind.ObjectCreationExpression);
            context.RegisterCompilationAction(AnalyzeIdentityModelDependencies);
        }

        private static void AnalyzeTypeCasing(SymbolAnalysisContext context)
        {
            // TODO: Replace the following code with your own analysis, generating Diagnostic objects for any issues you find
            var namedTypeSymbol = (INamedTypeSymbol)context.Symbol;

            // Find just those named type symbols with names containing lowercase letters.
            if (namedTypeSymbol.Name.ToCharArray().Any(char.IsLower))
            {
                // For all such symbols, produce a diagnostic.
                var diagnostic = Diagnostic.Create(Rule1, namedTypeSymbol.Locations[0], namedTypeSymbol.Name);

                context.ReportDiagnostic(diagnostic);
            }
        }

        private static void AnalyzeNestedStatements(SyntaxTreeAnalysisContext syntaxTreeContext)
        {
            // Iterate through all statements in the tree
            var root = syntaxTreeContext.Tree.GetRoot(syntaxTreeContext.CancellationToken);
            foreach (var statement in root.DescendantNodes().OfType<StatementSyntax>())
            {
                // Skip analyzing block statements 
                if (statement is BlockSyntax)
                {
                    continue;
                }

                // Report issues for all statements that are nested within a statement
                // but not a block statement
                if (statement.Parent is StatementSyntax && !(statement.Parent is BlockSyntax))
                {
                    var diagnostic = Diagnostic.Create(Rule2, statement.GetFirstToken().GetLocation());
                    syntaxTreeContext.ReportDiagnostic(diagnostic);
                }
            }
        }

        private static void AnalyzeJsonWebTokenCreation(SyntaxNodeAnalysisContext context)
        {
            var objectCreation = (ObjectCreationExpressionSyntax)context.Node;
            var typeSymbol = context.SemanticModel.GetSymbolInfo(objectCreation.Type).Symbol as INamedTypeSymbol;

            if (typeSymbol == null)
                return;

            // Check for JsonWebToken type (fully qualified name recommended)
            if (typeSymbol.ToDisplayString() == "Microsoft.IdentityModel.JsonWebTokens.JsonWebToken")
            {
                var diagnostic = Diagnostic.Create(Rule3, objectCreation.GetLocation(), typeSymbol.Name);
                context.ReportDiagnostic(diagnostic);
            }
        }

        private static void AnalyzeIdentityModelDependencies(CompilationAnalysisContext context)
        {
            var reference = context.Compilation.ReferencedAssemblyNames.First();
            var diagnostic = Diagnostic.Create(
                Rule4,
                Location.None,
                reference.Name,
                reference.Version?.ToString() ?? "unknown"
            );
            context.ReportDiagnostic(diagnostic);

            //foreach (var reference in context.Compilation.ReferencedAssemblyNames)
            //{
            //    if (reference.Name.StartsWith("Microsoft.IdentityModel.", StringComparison.Ordinal))
            //    {
            //        var diagnostic = Diagnostic.Create(
            //            Rule4,
            //            Location.None,
            //            reference.Name,
            //            reference.Version?.ToString() ?? "unknown"
            //        );
            //        context.ReportDiagnostic(diagnostic);
            //    }
            //}
        }
    }
}
