// Copyright (c) Microsoft Corporation. All rights reserved.
// Licensed under the MIT License.

using System;
using System.Collections.Concurrent;
using System.Collections.Generic;
using System.Reflection;
using System.Security.Claims;
using System.Threading;
using System.Threading.Tasks;
using Microsoft.IdentityModel.JsonWebTokens;
using Microsoft.IdentityModel.TestUtils;
using Xunit;

namespace Microsoft.IdentityModel.Tokens.Tests
{
    public class TokenValidationResultTests
    {
        [Fact]
        public void GetSets()
        {
            TestUtilities.WriteHeader("TokenValidationResultTests.GetSets()");

            TokenValidationResult tokenValidationResult = new TokenValidationResult();
            Type type = typeof(TokenValidationResult);
            PropertyInfo[] properties = type.GetProperties();
            if (properties.Length != 10)
                Assert.Fail("Number of public fields has changed from 10 to: " + properties.Length + ", adjust tests");

            GetSetContext context =
                new GetSetContext
                {
                    PropertyNamesAndSetGetValue = new List<KeyValuePair<string, List<object>>>
                    {
                        new KeyValuePair<string, List<object>>("ClaimsIdentity", new List<object>{(CaseSensitiveClaimsIdentity)null, new CaseSensitiveClaimsIdentity(), new CaseSensitiveClaimsIdentity()}),
                        new KeyValuePair<string, List<object>>("Exception", new List<object>{(Exception)null, new Exception(), new Exception()}),
                        new KeyValuePair<string, List<object>>("Issuer",  new List<object>{(string)null, "issuer", "issuer2"}),
                        new KeyValuePair<string, List<object>>("IsValid", new List<object>{false, false, true}),
                        new KeyValuePair<string, List<object>>("SecurityToken", new List<object>{(SecurityToken)null, new JsonWebToken(Default.Jwt(Default.SecurityTokenDescriptor())), new JsonWebToken(Default.Jwt(Default.SecurityTokenDescriptor()))}),
                        new KeyValuePair<string, List<object>>("TokenContext", new List<object>{(CallContext)null, new CallContext(), new CallContext()}),
                        new KeyValuePair<string, List<object>>("TokenType", new List<object>{(string)null, "JWTToken", "JwtToken2"}),
                        new KeyValuePair<string, List<object>>("PropertyBag", new List<object>{ tokenValidationResult.PropertyBag })
                    },
                    Object = tokenValidationResult,
                };

            TestUtilities.GetSet(context);

            TestUtilities.AssertFailIfErrors("TokenValidationResultTests.GetSets", context.Errors);
        }

        // Ensure the same ClaimsIdentity object is returned when concurrent calls made to TokenValidationResult.
        [Fact]
        public void ClaimsIdentity_ConcurrencyTest()
        {
            // Arrange
            var numThreads = 10;
            var barrier = new Barrier(numThreads);
            var result = new TokenValidationResult();
            ConcurrentBag<ClaimsIdentity> allClaimsIdentity = new();
            List<Action> actions = [];

            for (int i = 0; i < numThreads; i++)
            {
                actions.Add(() =>
                {
                    barrier.SignalAndWait();
                    allClaimsIdentity.Add(result.ClaimsIdentity);
                });
            }

            // Act
            Parallel.Invoke(actions.ToArray());

            // Assert
            Assert.Equal(numThreads, allClaimsIdentity.Count);
            Assert.True(allClaimsIdentity.TryTake(out var controlClaimsIdentity));
            foreach (var claimsIdentity in allClaimsIdentity)
            {
                Assert.Same(controlClaimsIdentity, claimsIdentity);
            }
        }
    }
}
