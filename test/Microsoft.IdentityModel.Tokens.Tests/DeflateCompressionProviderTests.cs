// Copyright (c) Microsoft Corporation. All rights reserved.
// Licensed under the MIT License.

using System;
using System.IO;
using System.IO.Compression;
using System.Text;
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