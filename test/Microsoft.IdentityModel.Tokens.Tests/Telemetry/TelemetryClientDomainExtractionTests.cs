// Copyright (c) Microsoft Corporation. All rights reserved.
// Licensed under the MIT License.

using System;
using System.Collections.Generic;
using System.Linq;
using System.Diagnostics;
using Microsoft.IdentityModel.TestUtils;
using Microsoft.IdentityModel.Tokens;
using Xunit;

namespace Microsoft.IdentityModel.Telemetry.Tests
{
    public class TelemetryClientDomainExtractionTests
    {
        [Fact]
        public void DebugMethodCall()
        {
            // Debug what's happening with reflection
            var telemetryClientType = typeof(TelemetryClient);
            var methods = telemetryClientType.GetMethods(System.Reflection.BindingFlags.NonPublic | System.Reflection.BindingFlags.Static);
            
            var foundMethods = new List<string>();
            foreach (var m in methods)
            {
                foundMethods.Add($"{m.Name}({string.Join(", ", m.GetParameters().Select(p => p.ParameterType.Name))})");
            }
            
            // This should help us see what methods are available
            Assert.True(foundMethods.Count > 0, $"Available methods: {string.Join(", ", foundMethods)}");
            
            var method = telemetryClientType.GetMethod("GetMetadataAddressForTelemetry", 
                System.Reflection.BindingFlags.NonPublic | System.Reflection.BindingFlags.Static);
            
            Assert.NotNull(method); // This should pass if the method exists
            
            // Test the method directly
            var testUrl = "https://login.microsoftonline.com/common/v2.0/.well-known/openid-configuration";
            var result = (string)method.Invoke(null, new object[] { testUrl, true });
            
            // For now, let's just ensure it doesn't throw and see what we get
            Assert.NotNull(result);
        }

        [Theory]
        [InlineData("https://login.microsoftonline.com/common/v2.0/.well-known/openid-configuration")]
        [InlineData("https://accounts.google.com/.well-known/openid-configuration")]
        [InlineData("https://login.windows.net/common/.well-known/openid-configuration")]
        public void GetMetadataAddressForTelemetry_ErrorCase_ReturnsFullAddress(string fullAddress)
        {
            // Arrange
            var telemetryClient = new TelemetryClient();
            
            // Act - using reflection to call the private method with isSuccessCase = false
            var method = typeof(TelemetryClient).GetMethod("GetMetadataAddressForTelemetry", 
                System.Reflection.BindingFlags.NonPublic | System.Reflection.BindingFlags.Static);
            var result = (string)method.Invoke(null, new object[] { fullAddress, false });

            // Assert
            Assert.Equal(fullAddress, result);
        }

        [Theory]
        [InlineData("invalid-url")]
        [InlineData("")]
        [InlineData(null)]
        public void GetMetadataAddressForTelemetry_InvalidUrl_ReturnsOriginalString(string invalidUrl)
        {
            // Arrange
            var telemetryClient = new TelemetryClient();
            
            // Act - using reflection to call the private method
            var method = typeof(TelemetryClient).GetMethod("GetMetadataAddressForTelemetry", 
                System.Reflection.BindingFlags.NonPublic | System.Reflection.BindingFlags.Static);
            var result = (string)method.Invoke(null, new object[] { invalidUrl, true });

            // Assert
            Assert.Equal(invalidUrl, result);
        }

        [Fact]
        public void GetMetadataAddressForTelemetry_WithAppContextSwitch_ReturnsFullAddress()
        {
            // Arrange
            var fullAddress = "https://login.microsoftonline.com/common/v2.0/.well-known/openid-configuration";
            var telemetryClient = new TelemetryClient();
            
            try
            {
                // Enable the switch to use full metadata address
                AppContext.SetSwitch(AppContextSwitches.UseFullMetadataAddressForTelemetrySwitch, true);
                
                // Act - using reflection to call the private method
                var method = typeof(TelemetryClient).GetMethod("GetMetadataAddressForTelemetry", 
                    System.Reflection.BindingFlags.NonPublic | System.Reflection.BindingFlags.Static);
                var result = (string)method.Invoke(null, new object[] { fullAddress, true });

                // Assert
                Assert.Equal(fullAddress, result);
            }
            finally
            {
                // Cleanup
                AppContext.SetSwitch(AppContextSwitches.UseFullMetadataAddressForTelemetrySwitch, false);
            }
        }

        [Fact]
        public void TelemetryClient_Methods_DoNotThrow()
        {
            // This test ensures that the modified telemetry methods don't break existing functionality
            // We cannot easily verify the exact values sent to the telemetry system without complex setup,
            // but we can ensure the methods don't throw exceptions when called with valid parameters.
            
            // Arrange
            var telemetryClient = new TelemetryClient();
            var testAddress = "https://login.microsoftonline.com/common/v2.0/.well-known/openid-configuration";
            var testDuration = TimeSpan.FromMilliseconds(100);
            var testException = new InvalidOperationException("Test exception");
            
            // Act & Assert - these should not throw
            var ex1 = Record.Exception(() => telemetryClient.LogConfigurationRetrievalDuration(testAddress, "Retriever", testDuration));
            var ex2 = Record.Exception(() => telemetryClient.LogConfigurationRetrievalDuration(testAddress, "Retriever", testDuration, testException));
            var ex3 = Record.Exception(() => telemetryClient.IncrementConfigurationRefreshRequestCounter(testAddress, "FirstRefresh", "Retriever"));
            var ex4 = Record.Exception(() => telemetryClient.IncrementConfigurationRefreshRequestCounter(testAddress, "ConfigurationRetrievalFailed", "Retriever", testException));
            var ex5 = Record.Exception(() => telemetryClient.LogBackgroundConfigurationRefreshFailure(testAddress, "Retriever", testException));
            
            Assert.Null(ex1);
            Assert.Null(ex2);
            Assert.Null(ex3);
            Assert.Null(ex4);
            Assert.Null(ex5);
        }

        [Fact]
        public void TelemetryClient_WithAppContextSwitch_DoesNotThrow()
        {
            // Test that telemetry methods work correctly when the backward compatibility switch is enabled
            
            try
            {
                // Enable the switch to use full metadata address
                AppContext.SetSwitch(AppContextSwitches.UseFullMetadataAddressForTelemetrySwitch, true);
                
                // Arrange
                var telemetryClient = new TelemetryClient();
                var testAddress = "https://accounts.google.com/.well-known/openid-configuration";
                var testDuration = TimeSpan.FromMilliseconds(150);
                var testException = new InvalidOperationException("Test exception");
                
                // Act & Assert - these should not throw even with the switch enabled
                var ex1 = Record.Exception(() => telemetryClient.LogConfigurationRetrievalDuration(testAddress, "Retriever", testDuration));
                var ex2 = Record.Exception(() => telemetryClient.LogConfigurationRetrievalDuration(testAddress, "Retriever", testDuration, testException));
                var ex3 = Record.Exception(() => telemetryClient.IncrementConfigurationRefreshRequestCounter(testAddress, "FirstRefresh", "Retriever"));
                var ex4 = Record.Exception(() => telemetryClient.IncrementConfigurationRefreshRequestCounter(testAddress, "ConfigurationRetrievalFailed", "Retriever", testException));
                var ex5 = Record.Exception(() => telemetryClient.LogBackgroundConfigurationRefreshFailure(testAddress, "Retriever", testException));
                
                Assert.Null(ex1);
                Assert.Null(ex2);
                Assert.Null(ex3);
                Assert.Null(ex4);
                Assert.Null(ex5);
            }
            finally
            {
                // Cleanup
                AppContext.SetSwitch(AppContextSwitches.UseFullMetadataAddressForTelemetrySwitch, false);
            }
        }
    }
}