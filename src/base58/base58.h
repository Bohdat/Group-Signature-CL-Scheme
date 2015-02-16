#ifndef _BASE_58_
#define _BASE_58_

#include <assert.h>
#include <string.h>
#include <vector>
#include <string>

/** All alphanumeric characters except for "0", "I", "O", and "l" */
static const char* pszBase58 = "123456789ABCDEFGHJKLMNPQRSTUVWXYZabcdefghijkmnopqrstuvwxyz";

std::string EncodeBase58(const unsigned char* pbegin, const unsigned char* pend);
bool DecodeBase58(const char* psz, std::vector<unsigned char>& vch);

std::string EncodeBase58(void* data, int len);
bool DecodeBase58(std::string code, void* data, int len);

#endif //_BASE_58_