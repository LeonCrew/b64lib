#include "b64lib.h"

#include <stdbool.h>
#include <assert.h>

#define B64LIB_FLAG_END 0x8000

static const unsigned char base64_enc_dict[64] = {
    'A','B','C','D','E','F','G','H','I','J','K','L','M','N','O','P',
    'Q','R','S','T','U','V','W','X','Y','Z','a','b','c','d','e','f',
    'g','h','i','j','k','l','m','n','o','p','q','r','s','t','u','v',
    'w','x','y','z','0','1','2','3','4','5','6','7','8','9','+','/'};

static const unsigned char base64url_enc_dict[64] = {
    'A','B','C','D','E','F','G','H','I','J','K','L','M','N','O','P',
    'Q','R','S','T','U','V','W','X','Y','Z','a','b','c','d','e','f',
    'g','h','i','j','k','l','m','n','o','p','q','r','s','t','u','v',
    'w','x','y','z','0','1','2','3','4','5','6','7','8','9','-','_'};

static const unsigned char hex_enc_dict[16] = {
    '0','1','2','3','4','5','6','7','8','9','a','b','c','d','e','f'};

static const unsigned char hexupper_enc_dict[16] = {
    '0','1','2','3','4','5','6','7','8','9','A','B','C','D','E','F'};

#define IN 0x80
#define WS 0xc0
#define EN 0x81

static const unsigned char base64_dec_dict[256] = {
/*        0   1   2   3   4   5   6   7   8   9   A   B   C   D   E   F */
/* 0x */  IN, IN, IN, IN, IN, IN, IN, IN, IN, WS, WS, WS, WS, WS, IN, IN,
/* 1x */  IN, IN, IN, IN, IN, IN, IN, IN, IN, IN, IN, IN, IN, IN, IN, IN,
/* 2x */  WS, IN, IN, IN, IN, IN, IN, IN, IN, IN, IN, 62, IN, IN, IN, 63,
/* 3x */  52, 53, 54, 55, 56, 57, 58, 59, 60, 61, IN, IN, IN, EN, IN, IN,
/* 4x */  IN,  0,  1,  2,  3,  4,  5,  6,  7,  8,  9, 10, 11, 12, 13, 14,
/* 5x */  15, 16, 17, 18, 19, 20, 21, 22, 23, 24, 25, IN, IN, IN, IN, IN,
/* 6x */  IN, 26, 27, 28, 29, 30, 31, 32, 33, 34, 35, 36, 37, 38, 39, 40,
/* 7x */  41, 42, 43, 44, 45, 46, 47, 48, 49, 50, 51, IN, IN, IN, IN, IN,
/* 8x */  IN, IN, IN, IN, IN, IN, IN, IN, IN, IN, IN, IN, IN, IN, IN, IN,
/* 9x */  IN, IN, IN, IN, IN, IN, IN, IN, IN, IN, IN, IN, IN, IN, IN, IN,
/* Ax */  IN, IN, IN, IN, IN, IN, IN, IN, IN, IN, IN, IN, IN, IN, IN, IN,
/* Bx */  IN, IN, IN, IN, IN, IN, IN, IN, IN, IN, IN, IN, IN, IN, IN, IN,
/* Cx */  IN, IN, IN, IN, IN, IN, IN, IN, IN, IN, IN, IN, IN, IN, IN, IN,
/* Dx */  IN, IN, IN, IN, IN, IN, IN, IN, IN, IN, IN, IN, IN, IN, IN, IN,
/* Ex */  IN, IN, IN, IN, IN, IN, IN, IN, IN, IN, IN, IN, IN, IN, IN, IN,
/* Fx */  IN, IN, IN, IN, IN, IN, IN, IN, IN, IN, IN, IN, IN, IN, IN, IN};

static const unsigned char base64url_dec_dict[256] = {
/*        0   1   2   3   4   5   6   7   8   9   A   B   C   D   E   F */
/* 0x */  IN, IN, IN, IN, IN, IN, IN, IN, IN, WS, WS, WS, WS, WS, IN, IN,
/* 1x */  IN, IN, IN, IN, IN, IN, IN, IN, IN, IN, IN, IN, IN, IN, IN, IN,
/* 2x */  WS, IN, IN, IN, IN, IN, IN, IN, IN, IN, IN, IN, IN, 62, IN, IN,
/* 3x */  52, 53, 54, 55, 56, 57, 58, 59, 60, 61, IN, IN, IN, EN, IN, IN,
/* 4x */  IN,  0,  1,  2,  3,  4,  5,  6,  7,  8,  9, 10, 11, 12, 13, 14,
/* 5x */  15, 16, 17, 18, 19, 20, 21, 22, 23, 24, 25, IN, IN, IN, IN, 63,
/* 6x */  IN, 26, 27, 28, 29, 30, 31, 32, 33, 34, 35, 36, 37, 38, 39, 40,
/* 7x */  41, 42, 43, 44, 45, 46, 47, 48, 49, 50, 51, IN, IN, IN, IN, IN,
/* 8x */  IN, IN, IN, IN, IN, IN, IN, IN, IN, IN, IN, IN, IN, IN, IN, IN,
/* 9x */  IN, IN, IN, IN, IN, IN, IN, IN, IN, IN, IN, IN, IN, IN, IN, IN,
/* Ax */  IN, IN, IN, IN, IN, IN, IN, IN, IN, IN, IN, IN, IN, IN, IN, IN,
/* Bx */  IN, IN, IN, IN, IN, IN, IN, IN, IN, IN, IN, IN, IN, IN, IN, IN,
/* Cx */  IN, IN, IN, IN, IN, IN, IN, IN, IN, IN, IN, IN, IN, IN, IN, IN,
/* Dx */  IN, IN, IN, IN, IN, IN, IN, IN, IN, IN, IN, IN, IN, IN, IN, IN,
/* Ex */  IN, IN, IN, IN, IN, IN, IN, IN, IN, IN, IN, IN, IN, IN, IN, IN,
/* Fx */  IN, IN, IN, IN, IN, IN, IN, IN, IN, IN, IN, IN, IN, IN, IN, IN};

static const unsigned char hex_dec_dict[256] = {
/*        0   1   2   3   4   5   6   7   8   9   A   B   C   D   E   F */
/* 0x */  IN, IN, IN, IN, IN, IN, IN, IN, IN, WS, WS, WS, WS, WS, IN, IN,
/* 1x */  IN, IN, IN, IN, IN, IN, IN, IN, IN, IN, IN, IN, IN, IN, IN, IN,
/* 2x */  WS, IN, IN, IN, IN, IN, IN, IN, IN, IN, IN, IN, IN, IN, IN, IN,
/* 3x */   0,  1,  2,  3,  4,  5,  6,  7,  8,  9, IN, IN, IN, IN, IN, IN,
/* 4x */  IN, 10, 11, 12, 13, 14, 15, IN, IN, IN, IN, IN, IN, IN, IN, IN,
/* 5x */  IN, IN, IN, IN, IN, IN, IN, IN, IN, IN, IN, IN, IN, IN, IN, IN,
/* 6x */  IN, 10, 11, 12, 13, 14, 15, IN, IN, IN, IN, IN, IN, IN, IN, IN,
/* 7x */  IN, IN, IN, IN, IN, IN, IN, IN, IN, IN, IN, IN, IN, IN, IN, IN,
/* 8x */  IN, IN, IN, IN, IN, IN, IN, IN, IN, IN, IN, IN, IN, IN, IN, IN,
/* 9x */  IN, IN, IN, IN, IN, IN, IN, IN, IN, IN, IN, IN, IN, IN, IN, IN,
/* Ax */  IN, IN, IN, IN, IN, IN, IN, IN, IN, IN, IN, IN, IN, IN, IN, IN,
/* Bx */  IN, IN, IN, IN, IN, IN, IN, IN, IN, IN, IN, IN, IN, IN, IN, IN,
/* Cx */  IN, IN, IN, IN, IN, IN, IN, IN, IN, IN, IN, IN, IN, IN, IN, IN,
/* Dx */  IN, IN, IN, IN, IN, IN, IN, IN, IN, IN, IN, IN, IN, IN, IN, IN,
/* Ex */  IN, IN, IN, IN, IN, IN, IN, IN, IN, IN, IN, IN, IN, IN, IN, IN,
/* Fx */  IN, IN, IN, IN, IN, IN, IN, IN, IN, IN, IN, IN, IN, IN, IN, IN};

struct b64lib_encode_struct
{
    int (*func)(b64lib_context* ctx, bool last);
    const unsigned char* dict;
    unsigned int flags;
    int length;
};

struct b64lib_decode_struct
{
    int (*func)(b64lib_context* ctx, bool last);
    const unsigned char* dict;
    unsigned int flags;
    int reserved;
};

static struct b64lib_encode_struct* b64lib_get_encode_struct(b64lib_context* ctx)
{
    assert(sizeof(struct b64lib_encode_struct) <= sizeof(ctx->internal));
    return (struct b64lib_encode_struct*)ctx->internal;
}

static struct b64lib_decode_struct* b64lib_get_decode_struct(b64lib_context* ctx)
{
    assert(sizeof(struct b64lib_decode_struct) <= sizeof(ctx->internal));
    return (struct b64lib_decode_struct*)ctx->internal;
}

/* Base64 */
static int b64lib_encode_base64(b64lib_context* ctx, bool last)
{
    struct b64lib_encode_struct* enc = b64lib_get_encode_struct(ctx);
    const unsigned char* dict = enc->dict;
    const unsigned char* inPtr = (const unsigned char*)(ctx->inBuffer);
    const unsigned char* inEnd = inPtr + ctx->inSize;
    unsigned char* outPtr = (unsigned char*)(ctx->outBuffer);
    unsigned char* outEnd = outPtr + ctx->outSize;
    const int maxLength = (enc->length >> 8) & 0xff;
    int curLength = enc->length & 0xff;
    
    while (inPtr < inEnd && outPtr < outEnd) {
        if (maxLength > 0 && maxLength <= curLength) {
            *outPtr++ = '\n';
            curLength = 0;
        }

        if ((inPtr + 2) >= inEnd || (outPtr + 3) >= outEnd)
            break;

        do {
            int value = *inPtr++ << 16;
            value |= *inPtr++ << 8;
            value |= *inPtr++;

            *outPtr++ = dict[(value >> 18) & 0x3f];
            *outPtr++ = dict[(value >> 12) & 0x3f];
            *outPtr++ = dict[(value >> 6) & 0x3f];
            *outPtr++ = dict[(value) & 0x3f];
            curLength += 4;
        } while ((inPtr + 2) < inEnd && (outPtr + 3) < outEnd && (maxLength == 0 || maxLength > curLength));
    }
    
    assert(inPtr <= inEnd);
    assert(outPtr <= outEnd);

    ctx->inBuffer = inPtr;
    ctx->outBuffer = outPtr;
    ctx->inSize = inEnd - inPtr;
    ctx->outSize = outEnd - outPtr;
    
    if (maxLength > 0)
        enc->length = maxLength << 8 | curLength;

    if (last) {
        if (ctx->inSize == 2 && ctx->outSize > 3) {
            int value = *inPtr++ << 16;
            value |= *inPtr++ << 8;

            *outPtr++ = dict[(value >> 18) & 0x3f];
            *outPtr++ = dict[(value >> 12) & 0x3f];
            *outPtr++ = dict[(value >> 6) & 0x3f];
            *outPtr++ = '=';
        } else if (ctx->inSize == 1 && ctx->outSize > 3) {
            int value = *inPtr++ << 16;

            *outPtr++ = dict[(value >> 18) & 0x3f];
            *outPtr++ = dict[(value >> 12) & 0x3f];
            *outPtr++ = '=';
            *outPtr++ = '=';
        } else if (ctx->inSize == 0) {
            // nothing to process
        } else {
            return B64LIB_ERROR_BUFFER;
        }
        
        ctx->inBuffer = inPtr;
        ctx->outBuffer = outPtr;
        ctx->inSize = inEnd - inPtr;
        ctx->outSize = outEnd - outPtr;
        
        if (maxLength > 0)
            enc->length = maxLength << 8 | curLength;
    }
    return B64LIB_ERROR_SUCCESS;
}

static int b64lib_decode_base64(b64lib_context* ctx, bool last)
{
    struct b64lib_decode_struct* dec = b64lib_get_decode_struct(ctx);
    const unsigned char* dict = dec->dict;
    const unsigned char* inPtr = (const unsigned char*)(ctx->inBuffer);
    const unsigned char* inEnd = inPtr + ctx->inSize;
    unsigned char* outPtr = (unsigned char*)(ctx->outBuffer);
    unsigned char* outEnd = outPtr + ctx->outSize;
    const bool base64url = dec->flags & B64LIB_MODE_BASE64URL;
    const bool skipWhitespace = dec->flags & B64LIB_SKIP_WHITESPACE;
    bool badStream = false;
    int endStream = 0;

    while (outPtr < outEnd && endStream == 0) {
        while (skipWhitespace && inPtr < inEnd && dict[*inPtr] == WS)
            ++inPtr;
        
        if ((inPtr + 3) >= inEnd || (outPtr + 2) >= outEnd)
            break;
        
        unsigned char d1 = dict[*inPtr++];
        unsigned char d2 = dict[*inPtr++];
        unsigned char d3 = dict[*inPtr++];
        unsigned char d4 = dict[*inPtr++];

        if (d4 == EN) {
            d4 = 0;
            endStream = 1;
            if (d3 == EN) {
                d3 = 0;
                endStream = 2;
            }
        }
        
        if ((d1 | d2 | d3 | d4) < 64) {
            const int value = (d1 << 18) | (d2 << 12) | (d3 << 6) | d4;
            
            if (endStream == 0) {
                *outPtr++ = (value >> 16) & 0xff;
                *outPtr++ = (value >> 8) & 0xff;
                *outPtr++ = (value) & 0xff;
            } else if (endStream == 1) {
                *outPtr++ = (value >> 16) & 0xff;
                *outPtr++ = (value >> 8) & 0xff;
            } else if (endStream == 2) {
                *outPtr++ = (value >> 16) & 0xff;
            }
            continue;
        }
        
        badStream = true;
        outPtr -= 4;
        break;
    }
    
    assert(inPtr <= inEnd);
    assert(outPtr <= outEnd);

    ctx->inBuffer = inPtr;
    ctx->outBuffer = outPtr;
    ctx->inSize = inEnd - inPtr;
    ctx->outSize = outEnd - outPtr;

    if (badStream)
        return B64LIB_ERROR_STREAM;
    
    if (endStream != 0)
        dec->flags |= B64LIB_FLAG_END;
    
    if (last) {
        if (ctx->inSize != 0)
            return B64LIB_ERROR_BUFFER;
    }
    return B64LIB_ERROR_SUCCESS;
}

/* HEX */
static int b64lib_encode_hex(b64lib_context* ctx, bool last)
{
    struct b64lib_encode_struct* enc = b64lib_get_encode_struct(ctx);
    const unsigned char* dict = enc->dict;
    const unsigned char* inPtr = (const unsigned char*)(ctx->inBuffer);
    const unsigned char* inEnd = inPtr + ctx->inSize;
    unsigned char* outPtr = (unsigned char*)(ctx->outBuffer);
    unsigned char* outEnd = outPtr + ctx->outSize;
    const int maxLength = (enc->length >> 8) & 0xff;
    int curLength = enc->length & 0xff;

    while (inPtr < inEnd && outPtr < outEnd) {
        if (maxLength > 0 && maxLength <= curLength) {
            *outPtr++ = '\n';
            curLength = 0;
        }
        
        while (inPtr < inEnd && (outPtr + 1) < outEnd && (maxLength == 0 || maxLength > curLength)) {
            const int value = *inPtr++;
            *outPtr++ = dict[(value >> 4) & 0xf];
            *outPtr++ = dict[(value) & 0xf];
            curLength += 2;
        }
    }
            
    assert(inPtr <= inEnd);
    assert(outPtr <= outEnd);

    ctx->inBuffer = inPtr;
    ctx->outBuffer = outPtr;
    ctx->inSize = inEnd - inPtr;
    ctx->outSize = outEnd - outPtr;
    
    if (maxLength > 0)
        enc->length = maxLength << 8 | curLength;

    if (last) {
        if (ctx->inSize != 0)
            return B64LIB_ERROR_BUFFER;
    }
    return B64LIB_ERROR_SUCCESS;
}

static int b64lib_decode_hex(b64lib_context* ctx, bool last)
{
    struct b64lib_decode_struct* dec = b64lib_get_decode_struct(ctx);
    const unsigned char* inPtr = (const unsigned char*)(ctx->inBuffer);
    const unsigned char* inEnd = inPtr + ctx->inSize;
    unsigned char* outPtr = (unsigned char*)(ctx->outBuffer);
    unsigned char* outEnd = outPtr + ctx->outSize;
    const bool skipWhitespace = dec->flags & B64LIB_SKIP_WHITESPACE;
    bool badStream = false;

    if (skipWhitespace) {
        while (outPtr < outEnd) {
            while (inPtr < inEnd && hex_dec_dict[*inPtr] == WS)
                ++inPtr;
            if ((inPtr + 1) >= inEnd)
                break;
            
            const unsigned char d1 = hex_dec_dict[*inPtr++];
            const unsigned char d2 = hex_dec_dict[*inPtr++];

            if ((d1 | d2) < 16) {
                *outPtr++ = (d1 << 4) | d2;
                continue;
            }

            badStream = true;
            inPtr -= 2;
            break;
        }
    } else {
        while (outPtr < outEnd && (inPtr + 1) < inEnd) {
            const unsigned char d1 = hex_dec_dict[*inPtr++];
            const unsigned char d2 = hex_dec_dict[*inPtr++];
            
            if ((d1 | d2) < 16) {
                *outPtr++ = (d1 << 4) | d2;
                continue;
            }

            badStream = true;
            inPtr -= 2;
            break;
        }
    }
    
    assert(inPtr <= inEnd);
    assert(outPtr <= outEnd);

    ctx->inBuffer = inPtr;
    ctx->outBuffer = outPtr;
    ctx->inSize = inEnd - inPtr;
    ctx->outSize = outEnd - outPtr;

    if (badStream)
        return B64LIB_ERROR_STREAM;
    
    if (last) {
        if (ctx->inSize != 0)
            return B64LIB_ERROR_BUFFER;
    }
    return B64LIB_ERROR_SUCCESS;
}

/* Encoder */
int b64lib_encode_init(b64lib_context* ctx, unsigned int flags)
{
    if (!ctx)
        return B64LIB_ERROR_CONTEXT;
    
    const unsigned int mode = flags & 0xf;
    const unsigned int length = flags & 0xf0;
    struct b64lib_encode_struct* enc = b64lib_get_encode_struct(ctx);

    if (mode == B64LIB_MODE_BASE64) {
        enc->func = &b64lib_encode_base64;
        enc->dict = base64_enc_dict;
    } else if (mode == B64LIB_MODE_BASE64URL) {
        enc->func = &b64lib_encode_base64;
        enc->dict = base64url_enc_dict;
    } else if (mode == B64LIB_MODE_HEX) {
        enc->func = &b64lib_encode_hex;
        enc->dict = hex_enc_dict;
    } else if (mode == B64LIB_MODE_HEXUPPER) {
        enc->func = &b64lib_encode_hex;
        enc->dict = hexupper_enc_dict;
    } else {
        return B64LIB_ERROR_ARGUMENT;
    }
    
    enc->flags = flags;

    if (length == B64LIB_LENGTH_64) {
        enc->length = 64 << 8;
    } else if (length == B64LIB_LENGTH_76) {
        enc->length = 76 << 8;
    } else {
        enc->length = 0;
    }
    
    ctx->inBuffer = 0;
    ctx->outBuffer = 0;
    ctx->inSize = 0;
    ctx->outSize = 0;
    
    return B64LIB_ERROR_SUCCESS;
}

int b64lib_encode_finish(b64lib_context* ctx)
{
    if (!ctx)
        return B64LIB_ERROR_CONTEXT;

    struct b64lib_encode_struct* enc = b64lib_get_encode_struct(ctx);
    if (enc->flags & B64LIB_FLAG_END)
        return B64LIB_ERROR_CONTEXT;

    int result = enc->func(ctx, true);
    
    if (result == B64LIB_ERROR_SUCCESS)
        enc->flags |= B64LIB_FLAG_END;
    
    return result;
}

int b64lib_encode(b64lib_context* ctx)
{
    if (!ctx)
        return B64LIB_ERROR_CONTEXT;

    struct b64lib_encode_struct* enc = b64lib_get_encode_struct(ctx);
    if (enc->flags & B64LIB_FLAG_END)
        return B64LIB_ERROR_CONTEXT;

    return enc->func(ctx, false);
}

/* Decoder */
int b64lib_decode_init(b64lib_context* ctx, unsigned int flags)
{
    if (!ctx)
        return B64LIB_ERROR_CONTEXT;
    
    const unsigned int mode = flags & 0xf;
    const unsigned int length = flags & 0xf0;
    struct b64lib_decode_struct* dec = b64lib_get_decode_struct(ctx);

    if (mode == B64LIB_MODE_BASE64) {
        dec->func = &b64lib_decode_base64;
        dec->dict = base64_dec_dict;
    } else if (mode == B64LIB_MODE_BASE64URL) {
        dec->func = &b64lib_decode_base64;
        dec->dict = base64url_dec_dict;
    } else if (mode == B64LIB_MODE_HEX || mode == B64LIB_MODE_HEXUPPER) {
        dec->func = &b64lib_decode_hex;
        dec->dict = 0;
    } else {
        return B64LIB_ERROR_ARGUMENT;
    }

    dec->reserved = 0;
    dec->flags = flags;
    
    ctx->inBuffer = 0;
    ctx->outBuffer = 0;
    ctx->inSize = 0;
    ctx->outSize = 0;
    
    return B64LIB_ERROR_SUCCESS;
}

int b64lib_decode_finish(b64lib_context* ctx)
{
    if (!ctx)
        return B64LIB_ERROR_CONTEXT;

    struct b64lib_decode_struct* dec = b64lib_get_decode_struct(ctx);
    if (dec->flags & B64LIB_FLAG_END)
        return B64LIB_ERROR_CONTEXT;

    int result = dec->func(ctx, true);
    
    if (result == B64LIB_ERROR_SUCCESS)
        dec->flags |= B64LIB_FLAG_END;
    
    return result;
}

int b64lib_decode(b64lib_context* ctx)
{
    if (!ctx)
        return B64LIB_ERROR_CONTEXT;

    struct b64lib_decode_struct* dec = b64lib_get_decode_struct(ctx);
    if (dec->flags & B64LIB_FLAG_END)
        return B64LIB_ERROR_CONTEXT;

    return dec->func(ctx, false);
}


/* Utility */
size_t b64lib_encode_size(size_t inSize, unsigned int flags)
{
    size_t outSize = 0;
    
    switch (flags & 0xf) {
        case B64LIB_MODE_BASE64:
        case B64LIB_MODE_BASE64URL:
            outSize = (inSize + 2) / 3 * 4;
            break;
        case B64LIB_MODE_HEX:
        case B64LIB_MODE_HEXUPPER:
            outSize = inSize * 2;
            break;
        default:
            break;
    }
    
    switch (flags & 0xf0) {
        case B64LIB_LENGTH_64:
            outSize += (outSize + 63) / 64;
            break;
        case B64LIB_LENGTH_76:
            outSize += (outSize + 75) / 76;
            break;
    }
    return outSize;
}

size_t b64lib_decode_size(size_t inSize, unsigned int flags)
{
    size_t outSize = 0;
    
    switch (flags & 0xf) {
        case B64LIB_MODE_BASE64:
        case B64LIB_MODE_BASE64URL:
            outSize = (inSize + 3) / 4 * 3;
            break;
        case B64LIB_MODE_HEX:
        case B64LIB_MODE_HEXUPPER:
            outSize = (inSize + 1) / 2;
            break;
        default:
            break;
    }
    return outSize;
}

int b64lib_encode_data(unsigned int flags, void* outBuffer, size_t outSize, size_t* outProcessed, const void* inBuffer, size_t inSize, size_t* inProcessed)
{
    b64lib_context ctx;
    int result = B64LIB_ERROR_SUCCESS;
    
    result = b64lib_encode_init(&ctx, flags);
    if (result != B64LIB_ERROR_SUCCESS)
        return result;
    
    ctx.inBuffer = inBuffer;
    ctx.inSize = inSize;
    ctx.outBuffer = outBuffer;
    ctx.outSize = outSize;
    
    result = b64lib_encode_finish(&ctx);
    
    if (outProcessed)
        *outProcessed = outSize - ctx.outSize;
    
    if (inProcessed)
        *inProcessed = inSize - ctx.inSize;
    
    return result;
}

int b64lib_decode_data(unsigned int flags, void* outBuffer, size_t outSize, size_t* outProcessed, const void* inBuffer, size_t inSize, size_t* inProcessed)
{
    b64lib_context ctx;
    int result = B64LIB_ERROR_SUCCESS;
    
    result = b64lib_decode_init(&ctx, flags);
    if (result != B64LIB_ERROR_SUCCESS)
        return result;
    
    ctx.inBuffer = inBuffer;
    ctx.inSize = inSize;
    ctx.outBuffer = outBuffer;
    ctx.outSize = outSize;
    
    result = b64lib_decode_finish(&ctx);
    
    if (outProcessed)
        *outProcessed = outSize - ctx.outSize;
    
    if (inProcessed)
        *inProcessed = inSize - ctx.inSize;
    
    return result;
}
