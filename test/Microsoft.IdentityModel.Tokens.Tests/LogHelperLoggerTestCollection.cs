// Copyright (c) Microsoft Corporation. All rights reserved.
// Licensed under the MIT License.

using Xunit;

namespace Microsoft.IdentityModel.Tokens.Tests
{
    /// <summary>
    /// Collection for tests that mutate the process-global <c>LogHelper.Logger</c> (or event-source log level).
    /// Marking them with <c>[Collection("LogHelper.Logger Tests")]</c> runs them serially so a concurrently
    /// running test cannot observe or restore the wrong logger.
    /// </summary>
    [CollectionDefinition("LogHelper.Logger Tests", DisableParallelization = true)]
    public class LogHelperLoggerTestCollection
    {
    }
}
