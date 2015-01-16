// HmacSha1.cpp

#include "StdAfx.h"
#include <stdio.h>
#include "HmacSha1.h"

namespace NCrypto {
namespace NSha1 {

void CHmac::SetKey(const Byte *key, size_t keySize)
{
  Byte keyTemp[kBlockSize];	//64
  size_t i;
  for (i = 0; i < kBlockSize; i++)
    keyTemp[i] = 0;
  if(keySize > kBlockSize)//impossible
  {
    _sha.Init();
    _sha.Update(key, keySize);
    _sha.Final(keyTemp);
    keySize = kDigestSize;
  }
  else
    for (i = 0; i < keySize; i++)
      keyTemp[i] = key[i];
  for (i = 0; i < kBlockSize; i++)
    keyTemp[i] ^= 0x36;
  _sha.Init();
  _sha.Update(keyTemp, kBlockSize);
  for (i = 0; i < kBlockSize; i++)
    keyTemp[i] ^= 0x36 ^ 0x5C;
  _sha2.Init();
  _sha2.Update(keyTemp, kBlockSize);
  printf("in set key buf sha1:%x %x   a~e: %x %x\n",_sha._buffer[0],_sha._buffer[1],_sha._state[0],_sha._state[1]);
  printf("in set key buf sha2:%x %x   a~e: %x %x\n",_sha2._buffer[0],_sha2._buffer[1],_sha2._state[0],_sha2._state[1]);
}

void CHmac::Final(Byte *mac, size_t macSize)
{
	Byte digest[kDigestSize]={0};//null
   

  printf("mac2_digest:%x%x%x%x%x%x%x%x%x%x\n",digest[0],digest[1],digest[2],digest[3],digest[4],digest[5],digest[6],digest[7],digest[8],digest[9]);
  _sha.Final(digest);
  printf("in  Final sha1:%x %x   a~e: %x %x\n",_sha._buffer[0],_sha._buffer[1],_sha._state[0],_sha._state[1]);
  printf("in  Final sha2:%x %x   a~e: %x %x\n",_sha2._buffer[0],_sha2._buffer[1],_sha2._state[0],_sha2._state[1]);
  printf("mac2_digestFinal:%x %x %x %x %x %x %x %x %x %x\n",digest[0],digest[1],digest[2],digest[3],digest[4],digest[5],digest[6],digest[7],digest[8],digest[9]);
  _sha2.Update(digest, kDigestSize);
  _sha2.Final(digest);
  printf("mac2_digestresult:%x%x%x%x%x%x%x%x%x%x\n",digest[0],digest[1],digest[2],digest[3],digest[4],digest[5],digest[6],digest[7],digest[8],digest[9]);
  for(size_t i = 0; i < macSize; i++)
    mac[i] = digest[i];
}

//key为密码
void CHmac32::SetKey(const Byte *key, size_t keySize)
{
  UInt32 keyTemp[kBlockSizeInWords];
  size_t i;
  for (i = 0; i < kBlockSizeInWords; i++)
    keyTemp[i] = 0;
  if(keySize > kBlockSize)//NOT
  {
	//printf("start1\n");
    CContext sha;
    sha.Init();

    sha.Update(key, keySize);
	//printf("end1\n");
    Byte digest[kDigestSize];
    sha.Final(digest);
    
    for (int i = 0 ; i < kDigestSizeInWords; i++)
      keyTemp[i] =
          ((UInt32)(digest[i * 4 + 0]) << 24) |
          ((UInt32)(digest[i * 4 + 1]) << 16) |
          ((UInt32)(digest[i * 4 + 2]) <<  8) |
          ((UInt32)(digest[i * 4 + 3]));
    keySize = kDigestSizeInWords;
  }
  else
    for (size_t i = 0; i < keySize; i++)
      keyTemp[i / 4] |= (key[i] << (24 - 8 * (i & 3)));
  for (i = 0; i < kBlockSizeInWords; i++)
    keyTemp[i] ^= 0x36363636;
  _sha.Init();

 // printf("start2\n");
  _sha.Update(keyTemp, kBlockSizeInWords);
  //printf("end2\n");
  for (i = 0; i < kBlockSizeInWords; i++)
    keyTemp[i] ^= 0x36363636 ^ 0x5C5C5C5C;
  _sha2.Init();

 // printf("start3\n");
  _sha2.Update(keyTemp, kBlockSizeInWords);
 // printf("end3\n");
  //printf("_buffer:%d%d%d%d%d%d%d%d%d%d\n",_sha2._buffer[0],_buffer[1],_buffer[2],_buffer[3],_buffer[4],_buffer[5],_buffer[6],_buffer[7],_buffer[8],_buffer[9]);
  //printf(" CHmac32::SetKey\n");
  //printf("in set key buf sha1:%x %x   a~e: %x %x\n",_sha._buffer[0],_sha._buffer[1],_sha._state[0],_sha._state[1]);
  //printf("in set key buf sha2:%x %x   a~e: %x %x\n",_sha2._buffer[0],_sha2._buffer[1],_sha2._state[0],_sha2._state[1]);
}

void CHmac32::Final(UInt32 *mac, size_t macSize)
{
//	  printf(" CHmac32::Final\n");
 // printf("in set key buf sha1:%x %x   a~e: %x %x\n",_sha._buffer[0],_sha._buffer[1],_sha._state[0],_sha._state[1]);
 // printf("in set key buf sha2:%x %x   a~e: %x %x\n",_sha2._buffer[0],_sha2._buffer[1],_sha2._state[0],_sha2._state[1]);
  UInt32 digest[kDigestSizeInWords];		//应该就是abcde吧
  _sha.Final(digest);
  _sha2.Update(digest, kDigestSizeInWords);
  _sha2.Final(digest);
  for(size_t i = 0; i < macSize; i++)
    mac[i] = digest[i];			//竟然第二次的sha1 是mac！！！！！  macSize=5
}

void CHmac32::GetLoopXorDigest(UInt32 *mac, UInt32 numIteration)
{
//		  printf(" CHmac32::GetLoopXorDigest\n");
//  printf("in set key buf sha1:%x %x   a~e: %x %x\n",_sha._buffer[0],_sha._buffer[1],_sha._state[0],_sha._state[1]);
 // printf("in set key buf sha2:%x %x   a~e: %x %x\n",_sha2._buffer[0],_sha2._buffer[1],_sha2._state[0],_sha2._state[1]);
  UInt32 block[kBlockSizeInWords];
  UInt32 block2[kBlockSizeInWords];
  _sha.PrepareBlock(block, kDigestSizeInWords);
  _sha2.PrepareBlock(block2, kDigestSizeInWords);
  for(unsigned int s = 0; s < kDigestSizeInWords; s++)
    block[s] = mac[s];
  for(UInt32 i = 0; i < numIteration; i++)
  {
    _sha.GetBlockDigest(block, block2);
    _sha2.GetBlockDigest(block2, block);
    for (unsigned int s = 0; s < kDigestSizeInWords; s++)
      mac[s] ^= block[s];
  }
}

}}
