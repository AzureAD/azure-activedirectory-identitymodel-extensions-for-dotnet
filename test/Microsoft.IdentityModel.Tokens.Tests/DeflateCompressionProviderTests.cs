// Copyright (c) Microsoft Corporation. All rights reserved.
// Licensed under the MIT License.

using System;
using System.Collections.Generic;
using System.IO;
using System.IO.Compression;
using System.Text;
using System.Text.Json;
using Xunit;

namespace Microsoft.IdentityModel.Tokens.Tests
{
    public class DeflateCompressionProviderTests
    {
        [Fact]
        public void DecompressLargePayload_ShouldSucceed()
        {
            // Create a large payload that would previously fail due to multiple Read calls needed
            var largeData = CreateLargeTestData(50000);
            
            var provider = new DeflateCompressionProvider();
            var compressedData = provider.Compress(Encoding.UTF8.GetBytes(largeData));
            var decompressedData = provider.Decompress(compressedData);
            var result = Encoding.UTF8.GetString(decompressedData);
            
            Assert.Equal(largeData, result);
        }

        [Fact]
        public void DecompressLargePayload_ExceedsMaximumSize_ShouldThrow()
        {
            // Create a payload and set a very small maximum size to trigger the error
            var data = CreateLargeTestData(1000);
            
            var provider = new DeflateCompressionProvider();
            provider.MaximumDeflateSize = 100; // Very small limit
            
            var compressedData = provider.Compress(Encoding.UTF8.GetBytes(data));
            
            // This should throw SecurityTokenDecompressionFailedException with IDX10816
            var exception = Assert.Throws<SecurityTokenDecompressionFailedException>(() => provider.Decompress(compressedData));
            Assert.Contains("IDX10816", exception.Message);
        }

        // Reproduces the original issue from https://github.com/AzureAD/azure-activedirectory-identitymodel-extensions-for-dotnet/issues/2516
        [Fact]
        public void DecompressLargePayload_IssueReproduction_ShouldSucceed()
        {
            // Create payload similar to the original issue scenario
            // Original issue used 100,000 iterations with 3 Data objects each (300,000 total items)
            // Using a smaller but still large enough payload to reproduce the issue
            var data = new List<object>();
            for (var i = 0; i < 30000; i++) // Reduced from 100,000 for test performance
            {
                data.Add(new { Prop1 = "Foo", Prop2 = 41 });
                data.Add(new { Prop1 = "Bar", Prop2 = 42 });
                data.Add(new { Prop1 = "Baz", Prop2 = 43 });
            }

            var payload = JsonSerializer.Serialize(data);
            var payloadBytes = Encoding.UTF8.GetBytes(payload);

            var provider = new DeflateCompressionProvider();
            
            // This would have thrown IDX10816 before the fix due to StreamReader.Read() 
            // not guaranteeing to return the maximum number of characters in a single call
            var compressedData = provider.Compress(payloadBytes);
            var decompressedData = provider.Decompress(compressedData);
            var result = Encoding.UTF8.GetString(decompressedData);
            
            Assert.Equal(payload, result);
        }

        private string CreateLargeTestData(int itemCount)
        {
            var sb = new StringBuilder();
            sb.Append('[');
            for (int i = 0; i < itemCount; i++)
            {
                if (i > 0) sb.Append(',');
                sb.Append($"{{\"Prop1\":\"TestValue{i}\",\"Prop2\":{i},\"Prop3\":\"SomeAdditionalDataToMakeItLarger{i}\"}}");
            }
            sb.Append(']');
            return sb.ToString();
        }
    }
}