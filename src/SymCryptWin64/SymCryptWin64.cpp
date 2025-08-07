#include "symcrypt.h"
#include <windows.h>
#include <stdexcept>
#include <vector>
#include <iostream>

// Declare the function prototype for GetSymCryptSha256AlgorithmAddress
extern "C" __declspec(dllexport) void* GetSymCryptSha256AlgorithmAddress();

// Exported function to create an RSA key and sign data using SymCrypt
// returns 0 on success, -1 on failure
extern "C" __declspec(dllexport) int CreateRsaKeyAndSign(
    const unsigned char* data,
    size_t dataLength,
    unsigned char* signature,
    size_t* signatureLength)
{
    if (!data || !signature || !signatureLength) {
        return -1;
    }

    PVOID sha256Algorithm = GetSymCryptSha256AlgorithmAddress();
    if (!sha256Algorithm) {
        return -2;
        //throw std::runtime_error("Failed to retrieve SHA-256 algorithm address.");
    }

    PCSYMCRYPT_HASH symCryptSha256Algorithm = reinterpret_cast<PCSYMCRYPT_HASH>(sha256Algorithm);

    // Define RSA parameters
    SYMCRYPT_RSA_PARAMS rsaParams = { 0 };
    rsaParams.version = 1;
    rsaParams.nBitsOfModulus = 2048; // 2048-bit RSA key
    rsaParams.nPrimes = 2;
    rsaParams.nPubExp = 1;

    // Allocate RSA key
    PSYMCRYPT_RSAKEY rsaKey = SymCryptRsakeyAllocate(&rsaParams, 0);
    if (!rsaKey) {
        return -3;
        //throw std::runtime_error("Failed to allocate RSA key.");
    }

    int rsaKeySize = SymCryptSizeofRsakeyFromParams(&rsaParams);
    PBYTE rsaKeyBuffer = new byte[rsaKeySize];
    long cb = (long)rsaKeySize;
    PSYMCRYPT_RSAKEY rsaKeyCreated = SymCryptRsakeyCreate(rsaKeyBuffer, cb, &rsaParams);

    // Generate RSA key
    int error = SymCryptRsakeyGenerate(rsaKeyCreated, 0, 0, 0);
    if (error != 0) {
        SymCryptRsakeyFree(rsaKeyCreated);
        return -4;
        //throw std::runtime_error("Failed to generate RSA key.");
    }

    // Hash the input data using SHA-256
    unsigned char hash[32] = { 0 };
    SymCryptSha256(data, dataLength, hash);

    // Sign the hash using RSA-PSS
    size_t maxSignatureSize = SymCryptRsakeySizeofModulus(rsaKeyCreated);
    std::vector<unsigned char> tempSignature(maxSignatureSize);

    size_t actualSignatureSize = 0;
    // Fix the issue by ensuring SymCryptSha256Algorithm is properly dereferenced as a function pointer.  
    error = SymCryptRsaPssSign(  
       rsaKey,  
       hash,  
       sizeof(hash),  
       symCryptSha256Algorithm,
       32, // Salt size  
       0,  // Flags  
       SYMCRYPT_NUMBER_FORMAT_MSB_FIRST,  
       tempSignature.data(),  
       tempSignature.size(),  
       &actualSignatureSize);

    if (error != 0) {
        SymCryptRsakeyFree(rsaKey);
        return -5;
    }

    // Copy the signature to the output buffer
    if (*signatureLength < actualSignatureSize) {
        SymCryptRsakeyFree(rsaKey);
        return -6;
    }

    memcpy(signature, tempSignature.data(), actualSignatureSize);
    *signatureLength = actualSignatureSize;

    // Free the RSA key
    SymCryptRsakeyFree(rsaKey);

    return 0; // Success
}

extern "C" __declspec(dllexport) void* GetSymCryptSha256AlgorithmAddress()
{
    HMODULE hSymCrypt = LoadLibraryA("SymCrypt.dll");
    if (!hSymCrypt)
    {
        std::cerr << "Failed to load SymCrypt.dll" << std::endl;
        return nullptr;
    }

    // If SymCryptSha256Algorithm is a function:
    FARPROC proc = GetProcAddress(hSymCrypt, "SymCryptSha256Algorithm");
    if (!proc)
    {
        std::cerr << "Failed to find SymCryptSha256Algorithm" << std::endl;
        FreeLibrary(hSymCrypt);
        return nullptr;
    }

    // If it's a variable, use reinterpret_cast to get the address
    return reinterpret_cast<void*>(proc);
}

