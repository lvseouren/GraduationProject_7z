// Extract.cpp

#include "StdAfx.h"
#include "iostream"
#include <stdio.h>

#include "Windows/FileDir.h"
#include "Windows/PropVariant.h"
#include "Windows/PropVariantConversions.h"

#include "../Common/ExtractingFilePath.h"

#include "Extract.h"
#include "SetProperties.h"

using namespace NWindows;

static HRESULT DecompressArchive(
    const CArc &arc,
    UInt64 packSize,
    const NWildcard::CCensorNode &wildcardCensor,
    const CExtractOptions &options,
    IExtractCallbackUI *callback,
    CArchiveExtractCallback *extractCallbackSpec,
    UString &errorMessage,
    UInt64 &stdInProcessed)
{
  stdInProcessed = 0;

  //����ʵ���˳���ṹ��Ĵ��麯��������
  IInArchive *archive = arc.Archive;   //ѡ��ѹ���ļ�
  CRecordVector<UInt32> realIndices;
  if (!options.StdInMode)
  {
    UInt32 numItems;

	//��ȡ����ѹ�������ļ��ĸ���
    RINOK(archive->GetNumberOfItems(&numItems));
    
	//ѹ�������ļ��ĸ���,numitems�����ļ�����    numItems=3
    for (UInt32 i = 0; i < numItems; i++)
    {
	 // std::cout<<"numItems!!!!!!!!!!!!!"<<numItems<<std::endl;
      UString filePath;
      RINOK(arc.GetItemPath(i, filePath));    //��ʵ�ںϸ�PATH������ÿ���ļ����ļ���
	  //std::wcout<<"PATH������������"<<*filePath<<std::endl;
      bool isFolder;
      RINOK(IsArchiveItemFolder(archive, i, isFolder));
      if (!wildcardCensor.CheckPath(filePath, !isFolder))
        continue;
      realIndices.Add(i);
    }
    if (realIndices.Size() == 0)
    {
      callback->ThereAreNoFiles();
      return S_OK;
    }
  }

  UStringVector removePathParts;

  FString outDir = options.OutputDir;
  outDir.Replace(FSTRING_ANY_MASK, us2fs(GetCorrectFsPath(arc.DefaultName)));   //�������Ŀ¼����
  #ifdef _WIN32
  // GetCorrectFullFsPath doesn't like "..".
  // outDir.TrimRight();
  // outDir = GetCorrectFullFsPath(outDir);
  #endif

  if (!outDir.IsEmpty())
	  //δִ�У��������Ŀ¼����
    if (!NFile::NDirectory::CreateComplexDirectory(outDir))
    {
      HRESULT res = ::GetLastError();
      if (res == S_OK)
        res = E_FAIL;
      errorMessage = ((UString)L"Can not create output directory ") + fs2us(outDir);
      return res;
    }


	
  //ִ���ˣ����ڵȵȷ���ʱ����������Ϣ��
  extractCallbackSpec->Init(
      options.StdInMode ? &wildcardCensor : NULL,
      &arc,
      callback,
      options.StdOutMode, options.TestMode, options.CalcCrc,
      outDir,
      removePathParts,
      packSize);    

  //here!!!!
  #if !defined(_7ZIP_ST) && !defined(_SFX)
 // std::cout<<"aaaaaa"<<std::endl;
  RINOK(SetProperties(archive, options.Properties));
  #endif

  HRESULT result;
  Int32 testMode = (options.TestMode && !options.CalcCrc) ? 1: 0;

  //û��ִ��
  if (options.StdInMode)
  {	
	//   std::cout<<"333333333333!!!!!!!!!!!!!"<<std::endl;
	//Extract���������ﱻ������
    result = archive->Extract(NULL, (UInt32)(Int32)-1, testMode, extractCallbackSpec);
    NCOM::CPropVariant prop;
    if (archive->GetArchiveProperty(kpidPhySize, &prop) == S_OK)
      if (prop.vt == VT_UI8 || prop.vt == VT_UI4)
        stdInProcessed = ConvertPropVariantToUInt64(prop);
  }
  else
	//goto the CArchiveExtractCallback::CryptoGetTextPassword����3�λ�ȡ�������룬����ʾ�����Ѵ�
    result = archive->Extract(&realIndices.Front(), realIndices.Size(), testMode, extractCallbackSpec);

  return callback->ExtractResult(result);
}

HRESULT DecompressArchives(
    CCodecs *codecs, const CIntVector &formatIndices,
    UStringVector &arcPaths, UStringVector &arcPathsFull,
    const NWildcard::CCensorNode &wildcardCensor,
    const CExtractOptions &options,
    IOpenCallbackUI *openCallback,
    IExtractCallbackUI *extractCallback,
    UString &errorMessage,
    CDecompressStat &stat)
{
  stat.Clear();
  int i;
  UInt64 totalPackSize = 0;
  CRecordVector<UInt64> archiveSizes;

  int numArcs = options.StdInMode ? 1 : arcPaths.Size();
  printf("the numArcs is %d\n",numArcs);//�о��ǲ��Ǳ�ʾ�ӱ�׼��������ļ�����һ���ļ�

  //if(options.StdInMode) std::cout<<"i guess it appear here"<<std::endl;

  for (i = 0; i < numArcs; i++)
  {
    NFile::NFind::CFileInfo fi;
    fi.Size = 0;
    if (!options.StdInMode)
    {
      const FString &arcPath = us2fs(arcPaths[i]);
      if (!fi.Find(arcPath))	//��������ļ�����
        throw "there is no such archive";
      if (fi.IsDir())
        throw "can't decompress folder";
    }
	std::cout<<"fi.Size :"<<fi.Size<<std::endl;   //���ѹ���ļ��Ĵ�С
    archiveSizes.Add(fi.Size);
    totalPackSize += fi.Size;
  }
  CArchiveExtractCallback *extractCallbackSpec = new CArchiveExtractCallback;   //һ�������˸�����Ϣ��ָ��
  CMyComPtr<IArchiveExtractCallback> ec(extractCallbackSpec);  //CMyComPtr����һ��ָ�롤������ָ����Զ�����ָ�룬�Լ�д��ģ����
 
  bool multi = (numArcs > 1);  //�Ƿ��ж���ļ�����Ȼ������
  extractCallbackSpec->InitForMulti(multi, options.PathMode, options.OverwriteMode);
  if (multi)
  {
    RINOK(extractCallback->SetTotal(totalPackSize));
  }

  //ѭ����ȡѹ����
  for (i = 0; i < numArcs; i++)    //һ��ѹ����
  {
	  std::cout<<"loop~"<<std::endl;
    const UString &arcPath = arcPaths[i];
    NFile::NFind::CFileInfo fi;
    if (options.StdInMode)
    {
	  //std::cout<<"i guess it appear here"<<std::endl;
      fi.Size = 0;
      fi.Attrib = 0;
    }
    else
    {
	   //	  std::cout<<"another way~"<<std::endl;
      if (!fi.Find(us2fs(arcPath)) || fi.IsDir())   //����������ļ�
        throw "there is no such archive";
    }

    #ifndef _NO_CRYPTO
    openCallback->Open_ClearPasswordWasAskedFlag();
    #endif
	//��������proseccing archive
	///////////////////////////////////////////////////////////////////////////////////////////////////////

    RINOK(extractCallback->BeforeOpen(arcPath));
    CArchiveLink archiveLink;  //Ҳ��һ����ѹ���ļ���Ϣ�Ķ��������Ϊѹ���ļ�����

    CIntVector formatIndices2 = formatIndices;
    #ifndef _SFX
	
    if (formatIndices.IsEmpty())
    {	
		//in �������еģ�
      int pos = arcPath.ReverseFind(L'.');
      if (pos >= 0)
      {
        UString s = arcPath.Mid(pos + 1);
		//std::wcout<<*(s+1)<<std::endl;
        int index = codecs->FindFormatForExtension(s);  //���ݺ�׺���ҵ���Ӧ����

        if (index >= 0 && s == L"001")
        { //not in
          s = arcPath.Left(pos);
          pos = s.ReverseFind(L'.');
          if (pos >= 0)
          {
            int index2 = codecs->FindFormatForExtension(s.Mid(pos + 1));
            if (index2 >= 0 && s.CompareNoCase(L"rar") != 0)
            {
              formatIndices2.Add(index2);
              formatIndices2.Add(index);
            }
          }
        }
      }
    }
    #endif
    HRESULT result = archiveLink.Open2(codecs, formatIndices2, options.StdInMode, NULL, arcPath, openCallback);  //����Ƚϸ��ӣ������ܵ���˵���ǻ�ȡ�ļ�����Ϣ
    //std::cout<<"check result:"<<result<<std::endl;    
	if (result == E_ABORT)
      return result;
	//��ʱ�������
    bool crypted = false;
    #ifndef _NO_CRYPTO
    crypted = openCallback->Open_WasPasswordAsked();  //�����Ƿ����
    #endif

    RINOK(extractCallback->OpenResult(arcPath, result, crypted));  //�鿴���봦�������е㲻һ������Ϊ��������������뷽ʽ�ʺ��жϵġ�
    if (result != S_OK)
      continue;

    if (!options.StdInMode)
    for (int v = 0; v < archiveLink.VolumePaths.Size(); v++)   //size �� 1�� Ŀ�����м����ļ�
    {
		//std::cout<<"here i m:"<<archiveLink.VolumePaths.Size()<<std::endl;
      int index = arcPathsFull.FindInSorted(archiveLink.VolumePaths[v]);  //������Ӧ�����ҵ�����ļ��������ݽṹ�ĺδ�
	 // std::cout<<"index:"<<index<<std::endl;
      if (index >= 0 && index > i)
      {
		//  std::cout<<"here i m:"<<archiveLink.VolumePaths.Size()<<std::endl;  //not in
        arcPaths.Delete(index);
        arcPathsFull.Delete(index);
        totalPackSize -= archiveSizes[index];
        archiveSizes.Delete(index);
        numArcs = arcPaths.Size();
      }
    }
    if (archiveLink.VolumePaths.Size() != 0)
    {
      totalPackSize += archiveLink.VolumesSize;
      RINOK(extractCallback->SetTotal(totalPackSize));
    }

    #ifndef _NO_CRYPTO
    UString password;
    RINOK(openCallback->Open_GetPasswordIfAny(password));//��ȡ���������
	//std::wcout<<" password here:"<<*password<<std::endl;     this is an empty password
    if (!password.IsEmpty())
    {
	  //std::cout<<"get password here"<<std::endl;
      RINOK(extractCallback->SetPassword(password));
    }
    #endif

	//ѭ���Ĵ���Ϊѹ����������
    for (int v = 0; v < archiveLink.Arcs.Size(); v++)          //size = 1
    {
	//	std::cout<<"Arcs.Size!!!!!!!!!!!!!"<<std::endl;
      const UString &s = archiveLink.Arcs[v].ErrorMessage;     //���ƿ�����û������
      if (!s.IsEmpty())
      {
        RINOK(extractCallback->MessageError(s));
      }
    }

    CArc &arc = archiveLink.Arcs.Back();  //�������һ��Ԫ��
    arc.MTimeDefined = (!options.StdInMode && !fi.IsDevice);
    arc.MTime = fi.MTime;

    UInt64 packProcessed;




	//��ȡ����ѹ���ļ���
    RINOK(DecompressArchive(arc,
        fi.Size + archiveLink.VolumesSize,
        wildcardCensor, options, extractCallback, extractCallbackSpec, errorMessage, packProcessed));





    if (!options.StdInMode)
      packProcessed = fi.Size + archiveLink.VolumesSize;
    extractCallbackSpec->LocalProgressSpec->InSize += packProcessed;   //�ļ����ܴ�С
    extractCallbackSpec->LocalProgressSpec->OutSize = extractCallbackSpec->UnpackSize;    //ÿ���ļ�ԭʼ��С�������ĺͣ�
	//std::cout<<"INSIZE "<<packProcessed<<" AND OUTSIZE��"<<extractCallbackSpec->UnpackSize<<std::endl;


    if (!errorMessage.IsEmpty())
      return E_FAIL;
  }
  stat.NumFolders = extractCallbackSpec->NumFolders;
  stat.NumFiles = extractCallbackSpec->NumFiles;
  stat.UnpackSize = extractCallbackSpec->UnpackSize;
  stat.CrcSum = extractCallbackSpec->CrcSum;

  stat.NumArchives = arcPaths.Size();
  stat.PackSize = extractCallbackSpec->LocalProgressSpec->InSize;
  return S_OK;
}
