// Copyright (c) Microsoft Corporation. All rights reserved.
// Licensed under the MIT License.

using System.Diagnostics;
using System.IO;
using Xunit;
using Xunit.Abstractions;

namespace Microsoft.IdentityModel.AotCompatibility.Tests
{
    public class AotCompatibilityTests
    {
        private ITestOutputHelper _testOutputHelper;

        public AotCompatibilityTests(ITestOutputHelper testOutputHelper)
        {
            _testOutputHelper = testOutputHelper;
        }

        /// <summary>
        /// This test ensures that the intended APIs of the Microsoft.IdentityModel libraries are
        /// trimming and NativeAOT compatible.
        ///
        /// This test follows the instructions in https://learn.microsoft.com/dotnet/core/deploying/trimming/prepare-libraries-for-trimming#show-all-warnings-with-sample-application
        ///
        /// If this test fails, it is due to adding trimming and/or AOT incompatible changes
        /// to code that is supposed to be compatible.
        /// 
        /// To diagnose the problem, inspect the test output which will contain the trimming and AOT errors. For example:
        ///
        /// error IL2091: 'T' generic argument does not satisfy 'DynamicallyAccessedMemberTypes.PublicConstructors'
        ///
        /// You can also 'dotnet publish' the 'Microsoft.IdentityModel.AotCompatibility.TestApp.csproj' as well to get the errors.
        /// </summary>
        [Fact]
        public void EnsureAotCompatibility()
        {
            string testAppPath = @"..\..\..\..\Microsoft.IdentityModel.AotCompatibility.TestApp";
            string testAppProject = "Microsoft.IdentityModel.AotCompatibility.TestApp.csproj";

            // ensure we run a clean publish every time
            DirectoryInfo testObjDir = new DirectoryInfo(Path.Combine(testAppPath, "obj"));
            if (testObjDir.Exists)
            {
                testObjDir.Delete(recursive: true);
            }

            var process = new Process();
            process.StartInfo = new ProcessStartInfo("dotnet", $"publish --self-contained {testAppProject}")
            {
                RedirectStandardOutput = true,
                UseShellExecute = false,
                CreateNoWindow = true,
                WorkingDirectory = testAppPath
            };
            process.OutputDataReceived += (sender, e) => _testOutputHelper.WriteLine(e.Data);
            process.Start();
            process.BeginOutputReadLine();

            Assert.True(process.WaitForExit(milliseconds: 30_000), "dotnet publish command timed out after 30 seconds.");

            Assert.True(process.ExitCode == 0, "Publishing the AotCompatibility app failed. See test output for more details.");
        }
    }
}
