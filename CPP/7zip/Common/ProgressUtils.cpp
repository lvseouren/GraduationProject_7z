// ProgressUtils.h

#include "StdAfx.h"
#include <iostream>
#include "ProgressUtils.h"

CLocalProgress::CLocalProgress()
{
  ProgressOffset = InSize = OutSize = 0;
  SendRatio = SendProgress = true;
}

void CLocalProgress::Init(IProgress *progress, bool inSizeIsMain)
{
  _ratioProgress.Release();
  _progress = progress;
  _progress.QueryInterface(IID_ICompressProgressInfo, &_ratioProgress);
  _inSizeIsMain = inSizeIsMain;
}

STDMETHODIMP CLocalProgress::SetRatioInfo(const UInt64 *inSize, const UInt64 *outSize)
{
	printf("ProgressUtils.cpp here !!!\n");
  UInt64 inSizeNew = InSize, outSizeNew = OutSize;
  if (inSize)
    inSizeNew += (*inSize);
  if (outSize)
    outSizeNew += (*outSize);
    std::cout<<"print inSizeNew look:"<<inSizeNew<<std::endl;  // 累计送进来的压缩文件大小
  std::cout<<"print outSizeNew look:"<<outSizeNew<<std::endl;  // 这个是未压缩文件大小

  if (SendRatio && _ratioProgress)
  {
	//   std::cout<<"In or Not"<<std::endl;			第二次调用时候就进来了，但是已经和解密没关系了
    RINOK(_ratioProgress->SetRatioInfo(&inSizeNew, &outSizeNew));
  }
  //std::cout<<"print ProgressOffset:"<<ProgressOffset<<std::endl;//一直都是0
  //感觉这里和解密关系不大啊····
  inSizeNew += ProgressOffset;
  outSizeNew += ProgressOffset;
  if (SendProgress)
    return _progress->SetCompleted(_inSizeIsMain ? &inSizeNew : &outSizeNew);
  return S_OK;
}

HRESULT CLocalProgress::SetCur()
{
  return SetRatioInfo(NULL, NULL);
}
