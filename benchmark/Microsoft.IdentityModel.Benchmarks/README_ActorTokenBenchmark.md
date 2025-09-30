# Actor Token Validation Performance Benchmarks

This document explains how to measure the performance impact of the `CanReadToken` checks added for actor token validation.

## Background

The security fix added `CanReadToken` checks before calling `ReadToken` in two places:
1. Actor token validation (line 324 in `JsonWebTokenHandler.ValidateToken.Internal.cs`)
2. Decrypted token validation (line 192 in `JsonWebTokenHandler.ValidateToken.Internal.cs`)

## Running the Benchmark

To measure the performance impact of these changes:

### 1. Run the Actor Token Validation Benchmark

```bash
cd benchmark/Microsoft.IdentityModel.Benchmarks
dotnet run -c Release -f net8.0 --filter "*ActorTokenValidationBenchmarks*"
```

### 2. Understand the Results

The benchmark measures several scenarios:

- **`ValidateToken_ValidActor`** (Baseline): Full validation of a token with a valid actor
- **`ValidateToken_LongActor_FastFail`**: Validation of a token with an overly long actor (should fail fast)
- **`ValidateToken_MalformedActor_FastFail`**: Validation of a token with a malformed actor (should fail fast)
- **`CanReadToken_ValidActor`**: Cost of the `CanReadToken` check itself for valid tokens
- **`CanReadToken_LongToken`**: Cost of the `CanReadToken` check for long tokens
- **`CanReadToken_MalformedToken`**: Cost of the `CanReadToken` check for malformed tokens

### 3. Performance Analysis

The benchmark will help you understand:

1. **Overhead for valid scenarios**: How much extra time the `CanReadToken` check adds to normal token validation
2. **Fast-fail benefits**: How much time is saved by failing fast on invalid tokens rather than attempting to parse them
3. **Validation cost**: The raw cost of the `CanReadToken` operation itself

### 4. Expected Results

- **Valid tokens**: Small overhead (microseconds) for the additional `CanReadToken` check
- **Invalid tokens**: Significant time savings by failing fast instead of attempting expensive parsing operations
- **Overall impact**: Net positive performance due to early rejection of malicious tokens

## Interpreting BenchmarkDotNet Output

Look for these key metrics:
- **Mean**: Average execution time
- **Error**: Standard error of the mean
- **StdDev**: Standard deviation
- **Ratio**: Performance relative to the baseline
- **Gen 0/1/2**: Garbage collection impact
- **Allocated**: Memory allocation

## Performance Expectations

The `CanReadToken` check should:
- Add minimal overhead (1-10 microseconds) for valid tokens
- Provide significant savings (100+ microseconds) for invalid tokens by avoiding expensive parsing
- Have minimal memory allocation impact

## Running Alternative Benchmarks

You can also run related benchmarks:

```bash
# All validation benchmarks
dotnet run -c Release -f net8.0 --filter "*ValidateTokenAsyncTests*"

# All JSON Web Token reading benchmarks  
dotnet run -c Release -f net8.0 --filter "*ReadJsonWebTokenBenchmarks*"
```

## Customizing the Benchmark

The benchmark can be customized by modifying `ActorTokenValidationBenchmarks.cs`:
- Adjust token sizes
- Test different claim sets
- Add more validation scenarios
- Measure different aspects of the validation pipeline