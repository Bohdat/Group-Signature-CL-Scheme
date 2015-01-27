#ifndef SHA1_DEFINED
#define SHA1_DEFINED
namespace sha1
{
    void calc(const void* src, const int bytelength, unsigned char* hash);
    void toHexString(const unsigned char* hash, char* hexstring);
}
#endif // SHA1_DEFINED
