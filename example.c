#include <stdio.h>
#include "b64lib.h"

const char originalString[] = "ABC123Test Lets Try this' input and see <What> \"happens\" !!??";

const char originalText[] = "ABC123Test Lets Try this' input and see <What> \"happens\" !!??\nABC123Test Lets Try this' input and see <What> \"happens\" !!??\nABC123Test Lets Try this' input and see <What> \"happens\" !!??\nABC123Test Lets Try this' input and see <What> \"happens\" !!??\nABC123Test Lets Try this' input and see <What> \"happens\" !!??";

void simpleBase64()
{
    unsigned char buffer[256] = {0};
    unsigned char buffer2[256] = {0};

    size_t encProcessed = 0;
    size_t decProcessed = 0;

    int errEnc = b64lib_encode_data(B64LIB_MODE_BASE64 | B64LIB_LENGTH_64, buffer, sizeof(buffer) - 1, &encProcessed, originalString, sizeof(originalString) - 1, 0);
    int errDec = b64lib_decode_data(B64LIB_MODE_BASE64 | B64LIB_SKIP_WHITESPACE, buffer2, sizeof(buffer2) - 1, &decProcessed, buffer, encProcessed, 0);

    printf("Simple Base64:\n- Original message: length: %ld\n%s\n- Encoded message: length: %ld, error code: %d\n%s\n- Decoded message: length: %ld, error code: %d\n%s\n\n",
        sizeof(originalString) - 1, originalString, encProcessed, errEnc, buffer, decProcessed, errDec, buffer2);
}

void simpleBase64Url()
{
    unsigned char buffer[256] = {0};
    unsigned char buffer2[256] = {0};

    size_t encProcessed = 0;
    size_t decProcessed = 0;

    int errEnc = b64lib_encode_data(B64LIB_MODE_BASE64URL | B64LIB_LENGTH_64, buffer, sizeof(buffer) - 1, &encProcessed, originalString, sizeof(originalString) - 1, 0);
    int errDec = b64lib_decode_data(B64LIB_MODE_BASE64URL | B64LIB_SKIP_WHITESPACE, buffer2, sizeof(buffer2) - 1, &decProcessed, buffer, encProcessed, 0);

    printf("Simple Base64Url:\n- Original message: length: %ld\n%s\n- Encoded message: length: %ld, error code: %d\n%s\n- Decoded message: length: %ld, error code: %d\n%s\n\n",
        sizeof(originalString) - 1, originalString, encProcessed, errEnc, buffer, decProcessed, errDec, buffer2);
}

void simpleHex()
{
    unsigned char buffer[256] = {0};
    unsigned char buffer2[256] = {0};
    
    size_t encProcessed = 0;
    size_t decProcessed = 0;

    int errEnc = b64lib_encode_data(B64LIB_MODE_HEX | B64LIB_LENGTH_64, buffer, sizeof(buffer) - 1, &encProcessed, originalString, sizeof(originalString) - 1, 0);
    int errDec = b64lib_decode_data(B64LIB_MODE_HEX | B64LIB_SKIP_WHITESPACE, buffer2, sizeof(buffer2) - 1, &decProcessed, buffer, encProcessed, 0);

    printf("Simple HEX:\n- Original message: length: %ld\n%s\n- Encoded message: length: %ld, error code: %d\n%s\n- Decoded message: length: %ld, error code: %d\n%s\n\n",
        sizeof(originalString) - 1, originalString, encProcessed, errEnc, buffer, decProcessed, errDec, buffer2);
}

void simpleHexUpper()
{
    unsigned char buffer[256] = {0};
    unsigned char buffer2[256] = {0};
    
    size_t encProcessed = 0;
    size_t decProcessed = 0;

    int errEnc = b64lib_encode_data(B64LIB_MODE_HEXUPPER | B64LIB_LENGTH_64, buffer, sizeof(buffer) - 1, &encProcessed, originalString, sizeof(originalString) - 1, 0);
    int errDec = b64lib_decode_data(B64LIB_MODE_HEXUPPER | B64LIB_SKIP_WHITESPACE, buffer2, sizeof(buffer2) - 1, &decProcessed, buffer, encProcessed, 0);

    printf("Simple HEX upper:\n- Original message: length: %ld\n%s\n- Encoded message: length: %ld, error code: %d\n%s\n- Decoded message: length: %ld, error code: %d\n%s\n\n",
        sizeof(originalString) - 1, originalString, encProcessed, errEnc, buffer, decProcessed, errDec, buffer2);
}

void heapBase64()
{
    size_t maxEncodedSize = b64lib_encode_size(sizeof(originalText) - 1, B64LIB_MODE_BASE64);
    unsigned char* encBuffer = malloc(maxEncodedSize + 1);
    
    b64lib_context ctx;

    b64lib_encode_init(&ctx, B64LIB_MODE_BASE64);
    ctx.inBuffer = originalText;
    ctx.inSize = sizeof(originalText) - 1;
    ctx.outBuffer = encBuffer;
    ctx.outSize = maxEncodedSize;
    
    int errEnc = b64lib_encode_finish(&ctx);
    size_t encodedSize = maxEncodedSize - ctx.outSize;
    size_t maxDecodedSize = b64lib_decode_size(encodedSize, B64LIB_MODE_BASE64);
    unsigned char* decBuffer = malloc(maxDecodedSize + 1);
    
    b64lib_decode_init(&ctx, B64LIB_MODE_BASE64);
    ctx.inBuffer = encBuffer;
    ctx.inSize = encodedSize;
    ctx.outBuffer = decBuffer;
    ctx.outSize = maxDecodedSize;

    int errDec = b64lib_decode_finish(&ctx);
    size_t decodedSize = maxDecodedSize - ctx.outSize;

    encBuffer[encodedSize] = 0;
    decBuffer[decodedSize] = 0;

    printf("Heap Base64:\n- Original message: length: %ld\n%s\n- Encoded message: length: %ld, error code: %d\n%s\n- Decoded message: length: %ld, error code: %d\n%s\n\n",
        sizeof(originalText) - 1, originalText, encodedSize, errEnc, encBuffer, decodedSize, errDec, decBuffer);

    free(decBuffer);
    free(encBuffer);
}

void iterBase64()
{
    unsigned char encBuffer[512] = {0};
    unsigned char decBuffer[512] = {0};
    size_t encodedSize = 0;
    size_t decodedSize = 0;
    b64lib_context ctx;

    b64lib_encode_init(&ctx, B64LIB_MODE_BASE64);
    
    ctx.inBuffer = originalText;
    ctx.inSize = sizeof(originalText) - 1;
    ctx.outBuffer = encBuffer;
    ctx.outSize = 20;

    while (b64lib_encode(&ctx) == B64LIB_ERROR_SUCCESS) {
        encodedSize += 20 - ctx.outSize;
        
        if (ctx.inSize > 0) {
            ctx.outSize = 20;
            continue;
        }
        break;
    }
    
    int errEnc = b64lib_encode_finish(&ctx);

    b64lib_decode_init(&ctx, B64LIB_MODE_BASE64);

    ctx.inBuffer = encBuffer;
    ctx.inSize = encodedSize;
    ctx.outBuffer = decBuffer;
    ctx.outSize = 20;

    while (b64lib_decode(&ctx) == B64LIB_ERROR_SUCCESS) {
        decodedSize += 20 - ctx.outSize;
        
        if (ctx.inSize > 0) {
            ctx.outSize = 20;
            continue;
        }
        break;
    }

    int errDec = b64lib_decode_finish(&ctx);

    encBuffer[encodedSize] = 0;
    decBuffer[decodedSize] = 0;

    printf("Iter Base64:\n- Original message: length: %ld\n%s\n- Encoded message: length: %ld, error code: %d\n%s\n- Decoded message: length: %ld, error code: %d\n%s\n\n",
        sizeof(originalText) - 1, originalText, encodedSize, errEnc, encBuffer, decodedSize, errDec, decBuffer);
}


int main(int argc, const char * argv[])
{
    printf("B64Lib example\n");
        
    simpleBase64();
    simpleBase64Url();
    simpleHex();
    simpleHexUpper();
    heapBase64();
    iterBase64();
    
    
    unsigned char buffer[256];
    size_t processed = 0;

    b64lib_encode_data(B64LIB_MODE_BASE64 | B64LIB_LENGTH_64, buffer, sizeof(buffer) - 1, &processed, originalString, sizeof(originalString) - 1, 0);
    buffer[processed] = 0;
    
    printf("Original message:\n%s\n\nEncoded message:\n%s\n", originalString, buffer);
    
    return 0;
}
