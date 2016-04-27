
#ifndef _b32_h_
#define _b32_h_

int base32_encode_length(int rawLength);
int base32_decode_length(int base32Length);
void base32_encode_into(const void *_buffer, unsigned int bufLen, char *base32Buffer);
int base32_decode_into(const char *base32Buffer, unsigned int base32BufLen, void *_buffer);
#endif
