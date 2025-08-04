// Copyright (c) Microsoft Corporation. All rights reserved.
// Licensed under the MIT License.

using System;
using System.IO;
using System.IO.Compression;
using System.Text;
using Microsoft.IdentityModel.TestUtils;
using Xunit;

namespace Microsoft.IdentityModel.Tokens.Tests
{
    public class DeflateCompressionProviderTests
    {
        [Fact]
        public void DecompressLargePayload_ShouldSucceed()
        {
            TestUtilities.WriteHeader($"{this}.DecompressLargePayload_ShouldSucceed");
            var context = new CompareContext($"{this}.DecompressLargePayload_ShouldSucceed");

            try
            {
                // Create a large payload that would previously fail due to multiple Read calls needed
                var largeData = CreateLargeTestData(50000);
                
                var provider = new DeflateCompressionProvider();
                var compressedData = provider.Compress(Encoding.UTF8.GetBytes(largeData));
                var decompressedData = provider.Decompress(compressedData);
                var result = Encoding.UTF8.GetString(decompressedData);
                
                if (!string.Equals(largeData, result))
                    context.AddDiff("Original data does not match decompressed data");
            }
            catch (Exception ex)
            {
                context.AddDiff($"Unexpected exception: {ex}");
            }

            TestUtilities.AssertFailIfErrors(context);
        }

        [Fact]
        public void DecompressLargePayload_ExceedsMaximumSize_ShouldThrow()
        {
            TestUtilities.WriteHeader($"{this}.DecompressLargePayload_ExceedsMaximumSize_ShouldThrow");
            var context = new CompareContext($"{this}.DecompressLargePayload_ExceedsMaximumSize_ShouldThrow");

            try
            {
                // Create a payload and set a very small maximum size to trigger the error
                var data = CreateLargeTestData(1000);
                
                var provider = new DeflateCompressionProvider();
                provider.MaximumDeflateSize = 100; // Very small limit
                
                var compressedData = provider.Compress(Encoding.UTF8.GetBytes(data));
                
                // This should throw SecurityTokenDecompressionFailedException with IDX10816
                provider.Decompress(compressedData);
                context.AddDiff("Expected SecurityTokenDecompressionFailedException was not thrown");
            }
            catch (SecurityTokenDecompressionFailedException ex)
            {
                // Expected exception - verify it contains IDX10816
                if (!ex.Message.Contains("IDX10816"))
                    context.AddDiff($"Expected IDX10816 error but got: {ex.Message}");
            }
            catch (Exception ex)
            {
                context.AddDiff($"Expected SecurityTokenDecompressionFailedException but got: {ex}");
            }

            TestUtilities.AssertFailIfErrors(context);
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