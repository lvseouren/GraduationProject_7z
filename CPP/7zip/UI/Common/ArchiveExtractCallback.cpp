// ArchiveExtractCallback.cpp

#include "StdAfx.h"
#include <iostream>
#include "Common/ComTry.h"
#include "Common/StringConvert.h"
#include "Common/Wildcard.h"

#include "Windows/FileDir.h"
#include "Windows/FileFind.h"
#include "Windows/FileName.h"
#include "Windows/PropVariant.h"
#include "Windows/PropVariantConversions.h"

#include "../../Common/FilePathAutoRename.h"

#include "../Common/ExtractingFilePath.h"

#include "ArchiveExtractCallback.h"

using namespace NWindows;

static const char *kCantAutoRename = "ERROR: Can not create file with auto name";
static const char *kCantRenameFile = "ERROR: Can not rename existing file ";
static const char *kCantDeleteOutputFile = "ERROR: Can not delete output file ";

void CArchiveExtractCallback::Init(
    const NWildcard::CCensorNode *wildcardCensor,
    const CArc *arc,
    IFolderArchiveExtractCallback *extractCallback2,
    bool stdOutMode, bool testMode, bool crcMode,
    const FString &directoryPath,
    const UStringVector &removePathParts,
    UInt64 packSize)
{
  _wildcardCensor = wildcardCensor;

  _stdOutMode = stdOutMode;
  _testMode = testMode;
  _crcMode = crcMode;
  _unpTotal = 1;
  _packTotal = packSize;

  _extractCallback2 = extractCallback2;
  _compressProgress.Release();
  _extractCallback2.QueryInterface(IID_ICompressProgressInfo, &_compressProgress);

  LocalProgressSpec->Init(extractCallback2, true);
  LocalProgressSpec->SendProgress = false;

 
  _removePathParts = removePathParts;
  _arc = arc;
  _directoryPath = directoryPath;
  NFile::NName::NormalizeDirPathPrefix(_directoryPath);
}

STDMETHODIMP CArchiveExtractCallback::SetTotal(UInt64 size)
{
  COM_TRY_BEGIN
  _unpTotal = size;
  if (!_multiArchives && _extractCallback2)
    return _extractCallback2->SetTotal(size);
  return S_OK;
  COM_TRY_END
}

static void NormalizeVals(UInt64 &v1, UInt64 &v2)
{
  const UInt64 kMax = (UInt64)1 << 31;
  while (v1 > kMax)
  {
    v1 >>= 1;
    v2 >>= 1;
  }
}

static UInt64 MyMultDiv64(UInt64 unpCur, UInt64 unpTotal, UInt64 packTotal)
{
  NormalizeVals(packTotal, unpTotal);
  NormalizeVals(unpCur, unpTotal);
  if (unpTotal == 0)
    unpTotal = 1;
  return unpCur * packTotal / unpTotal;
}

STDMETHODIMP CArchiveExtractCallback::SetCompleted(const UInt64 *completeValue)
{
	// std::cout<<"！！！CArchiveExtractCallback::SetCompleted"<<std::endl;   in here!
  COM_TRY_BEGIN
  if (!_extractCallback2)
    return S_OK;

  if (_multiArchives)
  {
    if (completeValue != NULL)
    {
      UInt64 packCur = LocalProgressSpec->InSize + MyMultDiv64(*completeValue, _unpTotal, _packTotal);
      return _extractCallback2->SetCompleted(&packCur);
    }
  }
  return _extractCallback2->SetCompleted(completeValue);
  COM_TRY_END
}

STDMETHODIMP CArchiveExtractCallback::SetRatioInfo(const UInt64 *inSize, const UInt64 *outSize)
{
  printf("Ar here or not!\n");
  COM_TRY_BEGIN
  return _localProgress->SetRatioInfo(inSize, outSize); //转到progressUtils/
  COM_TRY_END
}

void CArchiveExtractCallback::CreateComplexDirectory(const UStringVector &dirPathParts, FString &fullPath)
{
  fullPath = _directoryPath;
  for (int i = 0; i < dirPathParts.Size(); i++)
  {
    if (i > 0)
      fullPath += FCHAR_PATH_SEPARATOR;
    fullPath += us2fs(dirPathParts[i]);
    NFile::NDirectory::MyCreateDirectory(fullPath);
  }
}

HRESULT CArchiveExtractCallback::GetTime(int index, PROPID propID, FILETIME &filetime, bool &filetimeIsDefined)
{
  filetimeIsDefined = false;
  NCOM::CPropVariant prop;
  RINOK(_arc->Archive->GetProperty(index, propID, &prop));
  if (prop.vt == VT_FILETIME)
  {
    filetime = prop.filetime;
    filetimeIsDefined = (filetime.dwHighDateTime != 0 || filetime.dwLowDateTime != 0);
  }
  else if (prop.vt != VT_EMPTY)
    return E_FAIL;
  return S_OK;
}

HRESULT CArchiveExtractCallback::GetUnpackSize()
{
  return _arc->GetItemSize(_index, _curSize, _curSizeDefined);
}

HRESULT CArchiveExtractCallback::SendMessageError(const char *message, const FString &path)
{
  return _extractCallback2->MessageError(GetUnicodeString(message) + fs2us(path));
}

STDMETHODIMP CArchiveExtractCallback::GetStream(UInt32 index, ISequentialOutStream **outStream, Int32 askExtractMode)
{
	//std::cout<<"I WONDER IS HERE OR NOT"<<std::endl;     会进到这个函数
  COM_TRY_BEGIN
  _crcStream.Release();
  *outStream = 0;
  _outFileStream.Release();

  _encrypted = false;
  _isSplit = false;
  _curSize = 0;
  _curSizeDefined = false;
  _index = index;

  UString fullPath;

  IInArchive *archive = _arc->Archive;			//获取压缩文件
  RINOK(_arc->GetItemPath(index, fullPath));		//获取名字之类的
  RINOK(IsArchiveItemFolder(archive, index, _fi.IsDir));

  _filePath = fullPath;

  {
    NCOM::CPropVariant prop;
    RINOK(archive->GetProperty(index, kpidPosition, &prop));	//又是获取属性
    if (prop.vt != VT_EMPTY)
    {
      if (prop.vt != VT_UI8)
        return E_FAIL;
      _position = prop.uhVal.QuadPart;
      _isSplit = true;
    }
  }
    
  RINOK(GetArchiveItemBoolProp(archive, index, kpidEncrypted, _encrypted));	//里面又有get属性

  RINOK(GetUnpackSize());

  if (_wildcardCensor)
  {
    if (!_wildcardCensor->CheckPath(fullPath, !_fi.IsDir))
      return S_OK;
  }

  if (askExtractMode == NArchive::NExtract::NAskMode::kExtract && !_testMode)
  {
    if (_stdOutMode)
    {
      CMyComPtr<ISequentialOutStream> outStreamLoc = new CStdOutFileStream;
      *outStream = outStreamLoc.Detach();
      return S_OK;
    }

    {
      NCOM::CPropVariant prop;
      RINOK(archive->GetProperty(index, kpidAttrib, &prop));
      if (prop.vt == VT_UI4)
      {
        _fi.Attrib = prop.ulVal;
        _fi.AttribDefined = true;
      }
      else if (prop.vt == VT_EMPTY)
        _fi.AttribDefined = false;
      else
        return E_FAIL;
    }

    RINOK(GetTime(index, kpidCTime, _fi.CTime, _fi.CTimeDefined));
    RINOK(GetTime(index, kpidATime, _fi.ATime, _fi.ATimeDefined));
    RINOK(GetTime(index, kpidMTime, _fi.MTime, _fi.MTimeDefined));

    bool isAnti = false;
    RINOK(_arc->IsItemAnti(index, isAnti));

    UStringVector pathParts;
    SplitPathToParts(fullPath, pathParts);
    
    if (pathParts.IsEmpty())
      return E_FAIL;
    int numRemovePathParts = 0;
    switch(_pathMode)			//估计是分析输入参数的格式
    {
      case NExtract::NPathMode::kFullPathnames:
        break;
      case NExtract::NPathMode::kCurrentPathnames:
      {
		//std::cout<<"numRemovePathParts:"<<numRemovePathParts<<std::endl;			not in
        numRemovePathParts = _removePathParts.Size();
        if (pathParts.Size() <= numRemovePathParts)
          return E_FAIL;
        for (int i = 0; i < numRemovePathParts; i++)
          if (_removePathParts[i].CompareNoCase(pathParts[i]) != 0)
            return E_FAIL;
        break;
      }
      case NExtract::NPathMode::kNoPathnames:
      {
		//  std::cout<<"numRemovePathParts:"<<std::endl;				not in
        numRemovePathParts = pathParts.Size() - 1;
        break;
      }
    }
    pathParts.Delete(0, numRemovePathParts);
    MakeCorrectPath(pathParts);
    UString processedPath = MakePathNameFromParts(pathParts);
	//std::wcout<<"processedPath:"<<*processedPath<<std::endl;		就是文件名

    if (!isAnti)
    {
      if (!_fi.IsDir)
      {
        if (!pathParts.IsEmpty())
          pathParts.DeleteBack();
      }
    
      if (!pathParts.IsEmpty())
      {
        FString fullPathNew;
        CreateComplexDirectory(pathParts, fullPathNew);
        if (_fi.IsDir)
          NFile::NDirectory::SetDirTime(fullPathNew,
            (WriteCTime && _fi.CTimeDefined) ? &_fi.CTime : NULL,
            (WriteATime && _fi.ATimeDefined) ? &_fi.ATime : NULL,
            (WriteMTime && _fi.MTimeDefined) ? &_fi.MTime : (_arc->MTimeDefined ? &_arc->MTime : NULL));
      }
    }


    FString fullProcessedPath = _directoryPath + us2fs(processedPath);			//凑成一个全场的文件名

    if (_fi.IsDir)
    {
      _diskFilePath = fullProcessedPath;
      if (isAnti)
        NFile::NDirectory::MyRemoveDirectory(_diskFilePath);
      return S_OK;
    }

    if (!_isSplit)
    {
    NFile::NFind::CFileInfo fileInfo;
    if (fileInfo.Find(fullProcessedPath))			//此处要打开文件的！
    {
      switch(_overwriteMode)
      {
        case NExtract::NOverwriteMode::kSkipExisting:
          return S_OK;
        case NExtract::NOverwriteMode::kAskBefore:
        {
          Int32 overwiteResult;
		 // std::cout<<"check overwrite before"<<std::endl;
		  //覆盖就在这里了
          RINOK(_extractCallback2->AskOverwrite(
              fs2us(fullProcessedPath), &fileInfo.MTime, &fileInfo.Size, fullPath,
              _fi.MTimeDefined ? &_fi.MTime : NULL,
              _curSizeDefined ? &_curSize : NULL,
              &overwiteResult))
		  // std::cout<<"check overwrite after"<<std::endl;


		  //看选择什么处理现有文件的方式
          switch(overwiteResult)
          {
            case NOverwriteAnswer::kCancel:
              return E_ABORT;
            case NOverwriteAnswer::kNo:
              return S_OK;
            case NOverwriteAnswer::kNoToAll:
              _overwriteMode = NExtract::NOverwriteMode::kSkipExisting;
              return S_OK;
            case NOverwriteAnswer::kYesToAll:
              _overwriteMode = NExtract::NOverwriteMode::kWithoutPrompt;
              break;
            case NOverwriteAnswer::kYes:
              break;
            case NOverwriteAnswer::kAutoRename:
              _overwriteMode = NExtract::NOverwriteMode::kAutoRename;
              break;
            default:
              return E_FAIL;
          }
        }
      }
      if (_overwriteMode == NExtract::NOverwriteMode::kAutoRename)
      {
        if (!AutoRenamePath(fullProcessedPath))
        {
          RINOK(SendMessageError(kCantAutoRename, fullProcessedPath));
          return E_FAIL;
        }
      }
      else if (_overwriteMode == NExtract::NOverwriteMode::kAutoRenameExisting)
      {
        FString existPath = fullProcessedPath;
        if (!AutoRenamePath(existPath))
        {
          RINOK(SendMessageError(kCantAutoRename, fullProcessedPath));
          return E_FAIL;
        }
        if (!NFile::NDirectory::MyMoveFile(fullProcessedPath, existPath))
        {
          RINOK(SendMessageError(kCantRenameFile, fullProcessedPath));
          return E_FAIL;
        }
      }
      else
        if (!NFile::NDirectory::DeleteFileAlways(fullProcessedPath))
        {
          RINOK(SendMessageError(kCantDeleteOutputFile, fullProcessedPath));
          return S_OK;
          // return E_FAIL;
        }
    }
    }
    if (!isAnti)
    {
      _outFileStreamSpec = new COutFileStream;
      CMyComPtr<ISequentialOutStream> outStreamLoc(_outFileStreamSpec);
      if (!_outFileStreamSpec->Open(fullProcessedPath, _isSplit ? OPEN_ALWAYS: CREATE_ALWAYS))   //打开写出文件，处理压缩完的数据
      {
        // if (::GetLastError() != ERROR_FILE_EXISTS || !isSplit)
        {
          RINOK(SendMessageError("can not open output file ", fullProcessedPath));
          return S_OK;
        }
      }
      if (_isSplit)
      {
		//  std::cout<<"should not split"<<std::endl;    not in
        RINOK(_outFileStreamSpec->Seek(_position, STREAM_SEEK_SET, NULL));
      }
      _outFileStream = outStreamLoc;
      *outStream = outStreamLoc.Detach();
    }
    _diskFilePath = fullProcessedPath;
  }
  else
  {
    *outStream = NULL;
  }
  if (_crcMode)
  {
	//   std::cout<<"should not _crcMode"<<std::endl;    not in 
    _crcStreamSpec = new COutStreamWithCRC;
    _crcStream = _crcStreamSpec;
    CMyComPtr<ISequentialOutStream> crcStream = _crcStreamSpec;
    _crcStreamSpec->SetStream(*outStream);
    if (*outStream)
      (*outStream)->Release();
    *outStream = crcStream.Detach();
    _crcStreamSpec->Init(true);
  }
  return S_OK;
  COM_TRY_END
}

STDMETHODIMP CArchiveExtractCallback::PrepareOperation(Int32 askExtractMode)
{
  COM_TRY_BEGIN
  _extractMode = false;
  switch (askExtractMode)
  {
    case NArchive::NExtract::NAskMode::kExtract:
      if (_testMode)
        askExtractMode = NArchive::NExtract::NAskMode::kTest;
      else
        _extractMode = true;
      break;
  };
  return _extractCallback2->PrepareOperation(_filePath, _fi.IsDir,
      askExtractMode, _isSplit ? &_position: 0);
  COM_TRY_END
}

STDMETHODIMP CArchiveExtractCallback::SetOperationResult(Int32 operationResult)
{
  COM_TRY_BEGIN
  switch(operationResult)
  {
    case NArchive::NExtract::NOperationResult::kOK:
    case NArchive::NExtract::NOperationResult::kUnSupportedMethod:
    case NArchive::NExtract::NOperationResult::kCRCError:
    case NArchive::NExtract::NOperationResult::kDataError:
      break;
    default:
      _outFileStream.Release();
      return E_FAIL;
  }
  if (_crcStream)
  {
    CrcSum += _crcStreamSpec->GetCRC();
    _curSize = _crcStreamSpec->GetSize();
    _curSizeDefined = true;
    _crcStream.Release();
  }
  if (_outFileStream)
  {
    _outFileStreamSpec->SetTime(
        (WriteCTime && _fi.CTimeDefined) ? &_fi.CTime : NULL,
        (WriteATime && _fi.ATimeDefined) ? &_fi.ATime : NULL,
        (WriteMTime && _fi.MTimeDefined) ? &_fi.MTime : (_arc->MTimeDefined ? &_arc->MTime : NULL));
    _curSize = _outFileStreamSpec->ProcessedSize;
    _curSizeDefined = true;
    RINOK(_outFileStreamSpec->Close());
    _outFileStream.Release();
  }
  if (!_curSizeDefined)
    GetUnpackSize();
  if (_curSizeDefined)
    UnpackSize += _curSize;
  if (_fi.IsDir)
    NumFolders++;
  else
    NumFiles++;

  if (_extractMode && _fi.AttribDefined)
    NFile::NDirectory::MySetFileAttributes(_diskFilePath, _fi.Attrib);
  RINOK(_extractCallback2->SetOperationResult(operationResult, _encrypted));
  return S_OK;
  COM_TRY_END
}

/*
STDMETHODIMP CArchiveExtractCallback::GetInStream(
    const wchar_t *name, ISequentialInStream **inStream)
{
  COM_TRY_BEGIN
  CInFileStream *inFile = new CInFileStream;
  CMyComPtr<ISequentialInStream> inStreamTemp = inFile;
  if (!inFile->Open(_srcDirectoryPrefix + name))
    return ::GetLastError();
  *inStream = inStreamTemp.Detach();
  return S_OK;
  COM_TRY_END
}
*/

STDMETHODIMP CArchiveExtractCallback::CryptoGetTextPassword(BSTR *password)
{
  COM_TRY_BEGIN
   if (!_cryptoGetTextPassword)
  {
    RINOK(_extractCallback2.QueryInterface(IID_ICryptoGetTextPassword,
        &_cryptoGetTextPassword));
  }
  return _cryptoGetTextPassword->CryptoGetTextPassword(password);
  COM_TRY_END
}
