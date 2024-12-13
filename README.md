
# b64lib

Simple binary text converter library supporting base64, base64url, hex


![GitHub Downloads (all assets, latest release)](https://img.shields.io/github/downloads/LeonCrew/b64lib/latest/total)

  

## Example

Here is examle that encode input buffer to Base64:


~~~c
#include <stdio.h>
#include "b64lib.h"

int main(int argc, const char * _argv[])
{
    const char message[] = "ABC123Test Lets Try this' input and see_ <What> _\"happens\" !!??";
    unsigned char buffer[256];
    size_t processed = 0;

    b64lib_encode_data(B64LIB_MODE_BASE64 | B64LIB_LENGTH_64, buffer, sizeof(buffer) - 1, &processed, message, sizeof(message) - 1, 0);
    buffer[processed] = 0;

    printf("Original message:\n%s\n\nEncoded message:\n%s\n", message, buffer);
    return 0;
}
~~~
