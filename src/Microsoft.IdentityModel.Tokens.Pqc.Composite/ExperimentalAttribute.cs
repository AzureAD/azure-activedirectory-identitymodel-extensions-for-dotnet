// Copyright (c) Microsoft Corporation. All rights reserved.
// Licensed under the MIT License.

#nullable enable

#if !NET8_0_OR_GREATER
namespace System.Diagnostics.CodeAnalysis;

/// <summary>
/// Polyfill for the ExperimentalAttribute which is only available in .NET 8+.
/// Indicates that an API is experimental and may change in future versions.
/// </summary>
[AttributeUsage(
    AttributeTargets.Assembly | AttributeTargets.Module | AttributeTargets.Class |
    AttributeTargets.Struct | AttributeTargets.Enum | AttributeTargets.Constructor |
    AttributeTargets.Method | AttributeTargets.Property | AttributeTargets.Field |
    AttributeTargets.Event | AttributeTargets.Interface | AttributeTargets.Delegate,
    Inherited = false)]
internal sealed class ExperimentalAttribute : Attribute
{
    public ExperimentalAttribute(string diagnosticId)
    {
        DiagnosticId = diagnosticId;
    }

    public string DiagnosticId { get; }

    public string? UrlFormat { get; set; }
}
#endif
