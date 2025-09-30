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

The benchmark now includes **direct before/after comparisons** to measure the exact impact of the security fix:

#### Performance Comparison Benchmarks:
- **`ValidateToken_ValidActor_With_CanReadToken`** (Baseline): Current secure implementation with `CanReadToken` check
- **`ValidateToken_ValidActor_Without_CanReadToken`**: Original vulnerable implementation without the check
- **Direct comparison** showing the exact overhead introduced by the security fix

#### Fast-Fail Comparison Benchmarks:
- **`ValidateToken_LongActor_With_CanReadToken`**: Secure version that fails fast on oversized tokens
- **`ValidateToken_LongActor_Without_CanReadToken`**: Original version that attempts to parse oversized tokens
- **`ValidateToken_MalformedActor_With_CanReadToken`**: Secure version that fails fast on malformed tokens  
- **`ValidateToken_MalformedActor_Without_CanReadToken`**: Original version that attempts to parse malformed tokens

#### Raw Validation Cost Benchmarks:
- **`CanReadToken_ValidActor`**: Cost of the `CanReadToken` check for valid tokens
- **`CanReadToken_LongToken`**: Cost of the `CanReadToken` check for oversized tokens
- **`CanReadToken_MalformedToken`**: Cost of the `CanReadToken` check for malformed tokens

### 3. Performance Analysis

The benchmark will help you understand:

1. **Security overhead**: Exact time cost added by the `CanReadToken` security check for valid scenarios
2. **Fast-fail benefits**: Time saved by failing fast on invalid tokens vs. attempting expensive parsing
3. **Net performance impact**: Whether the security fix improves or degrades overall performance
4. **Validation efficiency**: Raw cost of the security validation operation

### 4. Expected Results

- **Valid tokens**: Small overhead (1-10 μs) for the additional `CanReadToken` check
- **Invalid tokens**: Significant time savings (50-500 μs) from fast-fail vs. attempted parsing
- **Overall impact**: Net positive performance due to early rejection of malicious tokens
- **Memory impact**: Reduced allocations from avoiding expensive parsing of invalid tokens

## Interpreting BenchmarkDotNet Output

Look for these key metrics in the comparison:

### For Valid Token Scenarios:
```
Method                                          Mean      Ratio
ValidateToken_ValidActor_With_CanReadToken     100.0 μs   1.00 (baseline)
ValidateToken_ValidActor_Without_CanReadToken   98.5 μs   0.99
```
- **Ratio < 1.00**: Security check adds minimal overhead
- **Ratio ≈ 1.00**: Negligible performance impact
- **Look for**: Overhead should be < 5% for valid scenarios

### For Invalid Token Scenarios:
```
Method                                              Mean      Ratio
ValidateToken_LongActor_With_CanReadToken          5.2 μs    1.00 (baseline)  
ValidateToken_LongActor_Without_CanReadToken     450.8 μs   86.69
```
- **Higher ratio for "Without"**: Shows time saved by fast-fail
- **Look for**: Significant performance improvement (10-100x faster) for invalid tokens

### Key Metrics:
- **Mean**: Average execution time - compare between with/without scenarios
- **Ratio**: Performance relative to baseline - shows exact overhead/benefit
- **Error/StdDev**: Measurement confidence - lower is better
- **Gen 0/1/2**: GC pressure - should be lower for fast-fail scenarios
- **Allocated**: Memory usage - should be lower for fast-fail scenarios

## Performance Expectations

The benchmark should demonstrate:

### For Valid Tokens:
- **Minimal overhead**: 1-10 μs additional cost for security check
- **Acceptable ratio**: 0.95-1.05 (within 5% of original performance)
- **Similar memory allocation**: No significant change in GC pressure

### For Invalid Tokens:
- **Significant performance gain**: 10-100x faster failure with security check
- **Reduced memory allocation**: Less GC pressure from avoiding failed parsing
- **Better scalability**: Reduced resource consumption under attack scenarios

## Running Alternative Benchmarks

You can also run related benchmarks for broader context:

```bash
# All validation benchmarks
dotnet run -c Release -f net8.0 --filter "*ValidateTokenAsyncTests*"

# All JSON Web Token reading benchmarks  
dotnet run -c Release -f net8.0 --filter "*ReadJsonWebTokenBenchmarks*"

# Focus on specific scenarios
dotnet run -c Release -f net8.0 --filter "*ValidateToken_ValidActor*"
dotnet run -c Release -f net8.0 --filter "*ValidateToken_LongActor*"
```

## Benchmark Implementation Details

The benchmark includes a `JsonWebTokenHandlerWithoutCanReadTokenCheck` class that replicates the original vulnerable behavior:
- Skips `CanReadToken` validation before calling `ReadToken`
- Attempts to parse all tokens regardless of size or format
- Provides accurate baseline for measuring security fix impact

This allows for precise measurement of the performance difference introduced by the security enhancement.

## Customizing the Benchmark

The benchmark can be customized by modifying `ActorTokenValidationBenchmarks.cs`:
- Adjust token sizes and complexity
- Test different claim sets and validation parameters
- Add more validation scenarios (encrypted tokens, nested actors, etc.)
- Measure different aspects of the validation pipeline
- Compare against other validation approaches