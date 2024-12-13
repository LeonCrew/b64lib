/*
 * b64lib - simple binary text converter library
 * Copyright (c) 2024 Alexandr Murashko
 *
 * Support:
 *  - base64
 *  - base64 for urls
 *  - hex (lower and upper case)
 */

#ifndef B64LIB_H_INCLUDED
#define B64LIB_H_INCLUDED

#include <stdlib.h>

#define B64LIB_VERSION_MAJOR 1
#define B64LIB_VERSION_MINOR 0
#define B64LIB_VERSION_PATCH 0

/* Errors: */
/* Operation is successful */
#define B64LIB_ERROR_SUCCESS    (0)
/* Invalid context argument or context is mark as finished */
#define B64LIB_ERROR_CONTEXT    (-1)
/* Invalid argument */
#define B64LIB_ERROR_ARGUMENT   (-2)
/* Input stream has invalid chars */
#define B64LIB_ERROR_STREAM     (-3)
/* Output buffer size is insufficient */
#define B64LIB_ERROR_BUFFER     (-4)

/* Flags: */
/* Base64 normal mode */
#define B64LIB_MODE_BASE64      0x0
/* Base64 urls mode */
#define B64LIB_MODE_BASE64URL   0x1
/* Hex mode */
#define B64LIB_MODE_HEX         0x2
/* Hex mode with upper case */
#define B64LIB_MODE_HEXUPPER    0x3
/* Split text line into 64 chars */
#define B64LIB_LENGTH_64        0x10
/* Split text line into 76 chars */
#define B64LIB_LENGTH_76        0x20
/* Skip whitespace in decode mode */
#define B64LIB_SKIP_WHITESPACE  0x40


#ifdef __cplusplus
extern "C" {
#endif /* __cplusplus */

typedef struct b64lib_context_struct
{
    const void* inBuffer;
    void* outBuffer;
    
    size_t inSize;
    size_t outSize;
 
    void* internal[4];
} b64lib_context;

/* Initialize context in encoder mode */
int b64lib_encode_init(b64lib_context* ctx, unsigned int flags);
/* Encode remain bytes from input buffer and mark context as finished */
int b64lib_encode_finish(b64lib_context* ctx);
/* Encode bytes from input buffer */
int b64lib_encode(b64lib_context* ctx);

/* Initialize context in decoder mode */
int b64lib_decode_init(b64lib_context* ctx, unsigned int flags);
/* Decode remain bytes from input buffer and mark context as finished */
int b64lib_decode_finish(b64lib_context* ctx);
/* Decode bytes from input buffer */
int b64lib_decode(b64lib_context* ctx);

/* Utility functions */

/* Upper bound on the encoded size by selected flags */
size_t b64lib_encode_size(size_t inSize, unsigned int flags);
/* Upper bound on the decoded size by selected flags */
size_t b64lib_decode_size(size_t inSize, unsigned int flags);

/* Encode inut buffer into the output buffer */
int b64lib_encode_data(unsigned int flags, void* outBuffer, size_t outSize, size_t* outProcessed, const void* inBuffer, size_t inSize, size_t* inProcessed);
/* Decode inut buffer into the output buffer */
int b64lib_decode_data(unsigned int flags, void* outBuffer, size_t outSize, size_t* outProcessed, const void* inBuffer, size_t inSize, size_t* inProcessed);

#ifdef __cplusplus
}
#endif /* __cplusplus */

#endif /* B64LIB_H_INCLUDED */
