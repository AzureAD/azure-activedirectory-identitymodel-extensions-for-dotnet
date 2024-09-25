﻿// Copyright (c) Microsoft Corporation. All rights reserved.
// Licensed under the MIT License.

using Microsoft.CodeAnalysis.Diagnostics;
using Microsoft.CodeAnalysis.Testing.Verifiers;
using Microsoft.CodeAnalysis.VisualBasic.Testing;

namespace Microsoft.IdentityModel.Analyzers.Test
{
    public static partial class VisualBasicAnalyzerVerifier<TAnalyzer>
        where TAnalyzer : DiagnosticAnalyzer, new()
    {
        public class Test : VisualBasicAnalyzerTest<TAnalyzer, MSTestVerifier>
        {
            public Test()
            {
            }
        }
    }
}
