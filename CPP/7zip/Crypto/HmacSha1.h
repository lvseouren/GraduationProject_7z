// HmacSha1.h
// Implements HMAC-SHA-1 (RFC2104, FIPS-198)

#ifndef __CRYPTO_HMAC_SHA1_H
#define __CRYPTO_HMAC_SHA1_H

#include "Sha1.h"

namespace NCrypto {
namespace NSha1 {

// Use:  SetKey(key, keySize); for () Update(data, size); Final(mac, macSize);

class CHmac
{
  
public:
	CContext _sha;
  CContext _sha2;
  void SetKey(const Byte *key, size_t keySize);
  void Update(const Byte *data, size_t dataSize) { _sha.Update(data, dataSize); }	//第一个的数据来进行sha1
  void Final(Byte *mac, size_t macSize = kDigestSize);
};

class CHmac32
{
  CContext32 _sha;			//sha 的结构，abcde  +  buf
  CContext32 _sha2;
public:
  void SetKey(const Byte *key, size_t keySize);
  void Update(const UInt32 *data, size_t dataSize) { _sha.Update(data, dataSize); }
  void Final(UInt32 *mac, size_t macSize = kDigestSizeInWords);
  
  // It'sa for hmac function. in,out: mac[kDigestSizeInWords].
  void GetLoopXorDigest(UInt32 *mac, UInt32 numIteration);
};

}}

#endif
