// Pbkdf2HmacSha1.cpp

#include "StdAfx.h"
#include <iostream>
#include "HmacSha1.h"
#include <stdio.h>

namespace NCrypto {
namespace NSha1 {

void Pbkdf2Hmac(const Byte *pwd, size_t pwdSize, const Byte *salt, size_t saltSize,
    UInt32 numIterations, Byte *key, size_t keySize)
{
  CHmac baseCtx;
  baseCtx.SetKey(pwd, pwdSize);
  for (UInt32 i = 1; keySize > 0; i++)
  {
    CHmac ctx = baseCtx;
    ctx.Update(salt, saltSize);
    Byte u[kDigestSize] = { (Byte)(i >> 24), (Byte)(i >> 16), (Byte)(i >> 8), (Byte)(i) };
    const unsigned int curSize = (keySize < kDigestSize) ? (unsigned int)keySize : kDigestSize;
    ctx.Update(u, 4);
    ctx.Final(u, kDigestSize);

    unsigned int s;
    for (s = 0; s < curSize; s++)
      key[s] = u[s];
    
    for (UInt32 j = numIterations; j > 1; j--)
    {
      ctx = baseCtx;
      ctx.Update(u, kDigestSize);
      ctx.Final(u, kDigestSize);
      for (s = 0; s < curSize; s++)
        key[s] ^= u[s];
    }

    key += curSize;
    keySize -= curSize;
  }
}

void Pbkdf2Hmac32(const Byte *pwd, size_t pwdSize, const UInt32 *salt, size_t saltSize,
    UInt32 numIterations, UInt32 *key, size_t keySize)	  //后面三个参数分别： 1000   后面两个是一个输出的buf   一个是大小   
{
  CHmac32 baseCtx;

  //update the _buffer of CContextBase2
//  printf("start \n");
  baseCtx.SetKey(pwd, pwdSize);		//这一步等于把两个block的sha都做了（有点像准备而已） ，一个是^0x36363636   一个是：^0x36363636 ^ 0x5c5c5c5c;然后存放起来
//  printf("end \n");
  for (UInt32 i = 1; keySize > 0; i++)
  {
    CHmac32 ctx = baseCtx;    //一些sha1的结构
	
    ctx.Update(salt, saltSize);			//等于进行salt的sha1处理了

	
    UInt32 u[kDigestSizeInWords] = { i };
    const unsigned int curSize = (keySize < kDigestSizeInWords) ? (unsigned int)keySize : kDigestSizeInWords;	//用于看循环放进多少个
	//std::cout<<"curSize :"<<curSize<<std::endl;   5.5.5.2
    ctx.Update(u, 1);	//到这里等于把U放进去block而已
    ctx.Final(u, kDigestSizeInWords);		//这里是进行大规模计算，有mac的，得到的u就是cpu里面的uu

    // Speed-optimized code start
    ctx = baseCtx;
    ctx.GetLoopXorDigest(u, numIterations - 1);		//一直到这里都是在获取ux而已！！！！
    // Speed-optimized code end
    
    unsigned int s;
    for (s = 0; s < curSize; s++)
      key[s] = u[s];				//相等于把ux存进kbuf里面，但是这里存的是17*4=68
    
    /*
    // Default code start
    for (UInt32 j = numIterations; j > 1; j--)
    {
      ctx = baseCtx;
      ctx.Update(u, kDigestSizeInWords);
      ctx.Final(u, kDigestSizeInWords);
      for (s = 0; s < curSize; s++)
        key[s] ^= u[s];
    }
    // Default code end
    */

    key += curSize;
    keySize -= curSize;
  }
}

}}
