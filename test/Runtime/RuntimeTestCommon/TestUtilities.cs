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

namespace RuntimeTestCommon
{
    public static class TestUtilities
    {
        /// <summary>
        /// Parses the command line args to retrieve the desired number of loops and iterations for the performance test.
        /// </summary>
        public static TestConfig ParseArgs(string[] args)
        {
            var perfRunConfig = new TestConfig();
            if (args == null || args.Length < 2)
                return perfRunConfig;

            var currentArg = 0;
            var displayArgs = false;
            for (int arg = 0; arg < args.Length; arg += 2)
            {
                if (args[currentArg].ToLower() == "-l")
                {
                    if (Int32.TryParse(args[currentArg + 1], out int numLoops))
                    {
                        perfRunConfig.NumLoops = numLoops;
                    }
                }
                else if (args[currentArg].ToLower() == "-i")
                {
                    if (Int32.TryParse(args[currentArg + 1], out int numIterations))
                        perfRunConfig.NumIterations = numIterations;
                }
                else if ((args[currentArg].ToLower() == "-h") || (args[currentArg].ToLower() == @"\?"))
                {
                    displayArgs = true;
                }
                else
                {
                    perfRunConfig.Logger.AppendLine($"Unknown Parameter: {args[currentArg]}");
                    displayArgs = true;
                }

                currentArg += 2;
            }

            if (displayArgs)
            {
                perfRunConfig.Logger.AppendLine("");
                perfRunConfig.Logger.AppendLine("*******************************************************");
                perfRunConfig.Logger.AppendLine($"Args: -l <numLoops>, -i <numIterations>, -h or /? help");
                perfRunConfig.Logger.AppendLine("");
                perfRunConfig.Logger.AppendLine("*******************************************************");
            }

            return perfRunConfig;
        }

        /// <summary>
        /// Prepares the specified test cases for testing.
        /// </summary>
        public static IList<TestRun> SetupTestRuns(List<TestExecutor> testExecutors)
        {
            var perfTestCases = new List<TestRun>();
            for (int i = 0; i < testExecutors.Count; i++)
            {
                perfTestCases.Add(new TestRun
                {
                    NumberOfIterationsRun = 0,
                    TotalTime = 0,
                    Name = testExecutors[i].Method.Name,
                    TestExecutor = testExecutors[i]
                });
            }

            return perfTestCases;
        }
    }
}
