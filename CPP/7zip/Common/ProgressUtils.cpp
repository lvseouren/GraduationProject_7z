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
    std::cout<<"print inSizeNew look:"<<inSizeNew<<std::endl;  // �ۼ��ͽ�����ѹ���ļ���С
  std::cout<<"print outSizeNew look:"<<outSizeNew<<std::endl;  // �����δѹ���ļ���С

  if (SendRatio && _ratioProgress)
  {
	//   std::cout<<"In or Not"<<std::endl;			�ڶ��ε���ʱ��ͽ����ˣ������Ѿ��ͽ���û��ϵ��
    RINOK(_ratioProgress->SetRatioInfo(&inSizeNew, &outSizeNew));
  }
  //std::cout<<"print ProgressOffset:"<<ProgressOffset<<std::endl;//һֱ����0
  //�о�����ͽ��ܹ�ϵ���󰡡�������
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
