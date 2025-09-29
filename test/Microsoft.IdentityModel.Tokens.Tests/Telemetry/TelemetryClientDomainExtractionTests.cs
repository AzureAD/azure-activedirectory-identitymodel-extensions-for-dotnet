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
        [Theory]
        [InlineData("https://login.microsoftonline.com/common/v2.0/.well-known/openid-configuration", "login.microsoftonline.com")]
        [InlineData("https://www.login.microsoftonline.com/common/v2.0/.well-known/openid-configuration", "login.microsoftonline.com")]
        [InlineData("https://accounts.google.com/.well-known/openid-configuration", "accounts.google.com")]
        [InlineData("https://login.windows.net/common/.well-known/openid-configuration", "login.windows.net")]  
        [InlineData("http://localhost:8080/.well-known/openid-configuration", "localhost")]
        [InlineData("https://example.com/path/to/config", "example.com")]
        [InlineData("https://subdomain.example.org/config.json", "subdomain.example.org")]
        public void GetMetadataAddressForTelemetry_SuccessCase_ReturnsExpectedDomain(string fullAddress, string expectedDomain)
        {
            // Act - using reflection to call the private method
            var method = typeof(TelemetryClient).GetMethod("GetMetadataAddressForTelemetry", 
                System.Reflection.BindingFlags.NonPublic | System.Reflection.BindingFlags.Static);
            var result = (string)method.Invoke(null, new object[] { fullAddress, true });

            // Assert
            Assert.Equal(expectedDomain, result);
        }

        [Fact]
        public void DebugAppContextSwitch()
        {
            // Check if the AppContext switch is causing issues
            var switchValue = AppContextSwitches.UseFullMetadataAddressForTelemetry;
            
            // Test a simple call
            var telemetryClientType = typeof(TelemetryClient);
            var method = telemetryClientType.GetMethod("GetMetadataAddressForTelemetry", 
                System.Reflection.BindingFlags.NonPublic | System.Reflection.BindingFlags.Static);
            
            var testUrl = "https://login.microsoftonline.com/common/v2.0/.well-known/openid-configuration";
            var result = (string)method.Invoke(null, new object[] { testUrl, true });
            
            // The switch should be false by default, so we should get the host name
            Assert.False(switchValue, $"Switch value: {switchValue}");
            Assert.Equal("login.microsoftonline.com", result);
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
                // Reset switches first to clear any cached values
                AppContextSwitches.ResetAllSwitches();
                
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
                AppContextSwitches.ResetAllSwitches();
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