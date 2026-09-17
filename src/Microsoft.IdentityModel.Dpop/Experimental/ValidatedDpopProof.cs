// Copyright (c) Microsoft Corporation. All rights reserved.
// Licensed under the MIT License.

using System;

#nullable enable
namespace Microsoft.IdentityModel.Dpop.Experimental;

internal sealed class ValidatedDpopProof
{
    internal ValidatedDpopProof(string jkt, string? nonce)
    {
        Jkt = jkt ?? throw new ArgumentNullException(nameof(jkt));
        Nonce = nonce;
    }

    internal string Jkt { get; }
    internal string? Nonce { get; }
}
