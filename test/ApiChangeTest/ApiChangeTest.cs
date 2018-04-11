//------------------------------------------------------------------------------
//
// Copyright (c) Microsoft Corporation.
// All rights reserved.
//
// This code is licensed under the MIT License.
//
// Permission is hereby granted, free of charge, to any person obtaining a copy
// of this software and associated documentation files(the "Software"), to deal
// in the Software without restriction, including without limitation the rights
// to use, copy, modify, merge, publish, distribute, sublicense, and / or sell
// copies of the Software, and to permit persons to whom the Software is
// furnished to do so, subject to the following conditions :
//
// The above copyright notice and this permission notice shall be included in
// all copies or substantial portions of the Software.
//
// THE SOFTWARE IS PROVIDED "AS IS", WITHOUT WARRANTY OF ANY KIND, EXPRESS OR
// IMPLIED, INCLUDING BUT NOT LIMITED TO THE WARRANTIES OF MERCHANTABILITY,
// FITNESS FOR A PARTICULAR PURPOSE AND NONINFRINGEMENT.IN NO EVENT SHALL THE
// AUTHORS OR COPYRIGHT HOLDERS BE LIABLE FOR ANY CLAIM, DAMAGES OR OTHER
// LIABILITY, WHETHER IN AN ACTION OF CONTRACT, TORT OR OTHERWISE, ARISING FROM,
// OUT OF OR IN CONNECTION WITH THE SOFTWARE OR THE USE OR OTHER DEALINGS IN
// THE SOFTWARE.
//
//------------------------------------------------------------------------------

using System;
using System.Collections.Generic;
using System.IO;
using System.Reflection;
using System.Text;
using System.Xml.Linq;
using ApiCheck;
using ApiCheck.Configuration;
using ApiCheck.Loader;
using ApiCheck.Result.Difference;
using Microsoft.IdentityModel.Tests;
using Xunit;

#pragma warning disable CS3016 // Arrays as attribute arguments is not CLS-compliant

namespace ApiChangeTest
{
    public class ApiChangeTest
    {
        private static bool _readyToRunTests = false;

        private static List<string> _packagesToCheck = new List<string>()
        {
            "Microsoft.IdentityModel.Logging",
            "Microsoft.IdentityModel.Protocols",
            "Microsoft.IdentityModel.Protocols.OpenIdConnect",
            "Microsoft.IdentityModel.Protocols.WsFederation",
            "Microsoft.IdentityModel.Tokens",
            "Microsoft.IdentityModel.Tokens.Saml",
            "Microsoft.IdentityModel.Xml",
            "System.IdentityModel.Tokens.Jwt"
        };

        // Add the list of allowed breaking changes here
        // Full name must be provided, i.e. namespace.className.propertyName
        private static List<string> _allowedApiBreakingChanges = new List<string>()
        {
            "System.IdentityModel.Tokens.Jwt.JwtSecurityTokenHandler.MaximumTokenSizeInBytes"
        };

        /// <summary>
        /// This function is used to create the directories needed for dev assemblies and reports, and copy
        /// dev assemblies into the devAssemblies directory.
        /// </summary>
        void PrepareTests()
        {
            if (_readyToRunTests)
                return;

            // create the directory to store dev assemblies
            Directory.CreateDirectory(Path.Combine(Directory.GetCurrentDirectory(), @"..\..\..\Resource\devAssemblies"));

            // create the directory for reports
            Directory.CreateDirectory(Path.Combine(Directory.GetCurrentDirectory(), @"..\..\..\Resource\reports"));

            var srcPath = Path.Combine(Directory.GetCurrentDirectory(), @"..\..\..\..\..\src\{0}\bin\Debug\net451\{0}.dll");
            var destPath = Path.Combine(Directory.GetCurrentDirectory(), @"..\..\..\Resource\devAssemblies\{0}.dll");

            foreach(var package in _packagesToCheck)
            {
                File.Copy(string.Format(srcPath, package), string.Format(destPath, package), true);
            }

            File.Copy(Path.Combine(Directory.GetCurrentDirectory(), @"..\..\..\..\..\src\System.IdentityModel.Tokens.Jwt\bin\Debug\net451\Newtonsoft.Json.dll"), string.Format(destPath, "Newtonsoft.Json"), true);

            _readyToRunTests = true;
        }

        void RunApiCheck(string packageName)
        {
            Console.WriteLine(">>>> Checking Api breaking change for: " + packageName + Environment.NewLine);

            var refAssemblyPath = Path.Combine(Directory.GetCurrentDirectory(), @"..\..\..\Resource\refAssemblies\" + packageName + ".dll");
            var devAssemblyPath = Path.Combine(Directory.GetCurrentDirectory(), @"..\..\..\Resource\devAssemblies\" + packageName + ".dll");
            var reportPath = Path.Combine(Directory.GetCurrentDirectory(), @"..\..\..\Resource\reports\" + packageName + ".report.xml");
            var sb = new StringBuilder();
            var succeed = true;

            try
            {
                using (AssemblyLoader assemblyLoader = new AssemblyLoader())
                {
                    // load assemblies
                    Assembly refAssembly = assemblyLoader.ReflectionOnlyLoad(refAssemblyPath);
                    Assembly devAssembly = assemblyLoader.ReflectionOnlyLoad(devAssemblyPath);

                    // configuration
                    ComparerConfiguration configuration = new ComparerConfiguration();
                    configuration.Severities.ParameterNameChanged = Severity.Warning;
                    configuration.Severities.AssemblyNameChanged = Severity.Hint;
                    foreach(var allowedBreakingChange in _allowedApiBreakingChanges)
                        configuration.Ignore.Add(allowedBreakingChange);

                    // compare assemblies and write xml report
                    using (var stream = new FileStream(reportPath, FileMode.Create))
                    {
                        ApiComparer.CreateInstance(refAssembly, devAssembly)
                          .WithComparerConfiguration(configuration)
                          .WithDetailLogging(s => Console.WriteLine(s))
                          .WithInfoLogging(s => Console.WriteLine(s))
                          .WithXmlReport(stream)
                          .Build()
                          .CheckApi();
                    }
                }

                var scenarioList = new List<string>() { "ChangedAttribute", "ChangedElement", "RemovedElement" };

                // check the scenarios that we might have a breaking change
                foreach (var scenario in scenarioList)
                {
                    XElement doc = XElement.Load(reportPath);

                    foreach (XElement change in doc.Descendants(scenario))
                    {
                        if (change.Attribute("Severity") != null && "Error".Equals(change.Attribute("Severity").Value))
                        {
                            succeed = false;

                            // append the parent, for instance, 
                            if (change.Parent != null)
                                sb.AppendLine($"In {change.Parent.Attribute("Context").Value} : {change.Parent.Attribute("Name").Value}");

                            sb.AppendLine(change.ToString());
                        }
                    }
                }
            }
            catch(Exception ex)
            {
                throw new ApiChangeException("Assembly comparison failed.", ex);
            }

            if (!succeed)
                throw new ApiChangeException($"The following breaking changes are found: {Environment.NewLine} {sb.ToString()}");
        }

        [Theory, MemberData(nameof(ApiBreakingChangeTestTheoryData))]
        public void ApiBreakingChangeTest(ApiChangeTestTheoryData theoryData)
        {
            var context = TestUtilities.WriteHeader($"{this}.ApiBreakingChangeTest", theoryData);
            try
            {
                PrepareTests();
                RunApiCheck(theoryData.PackageName);
                theoryData.ExpectedException.ProcessNoException(context);
            }
            catch (Exception ex)
            {
                theoryData.ExpectedException.ProcessException(ex, context);
            }
            TestUtilities.AssertFailIfErrors(context);
        }

        public static TheoryData<ApiChangeTestTheoryData> ApiBreakingChangeTestTheoryData
        {
            get
            {
                var theoryData = new TheoryData<ApiChangeTestTheoryData>();
                foreach(var packageName in _packagesToCheck)
                {
                    theoryData.Add(new ApiChangeTestTheoryData()
                    {
                        PackageName = packageName
                    });
                }
                return theoryData;
            }
        }
    }

    public class ApiChangeTestTheoryData : TheoryDataBase
    {
        public string PackageName;
    }
}

#pragma warning restore CS3016 // Arrays as attribute arguments is not CLS-compliant
