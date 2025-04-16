#include"fh.h"  

using namespace std;

#define STRING(X) #X


int main()
{
	
	//IMAGE_SECTION_HEADER ish;
	IMAGE_IMPORT_DESCRIPTOR iid;	//导入描述符
	IMAGE_IMPORT_BY_NAME iibn;		
	IMAGE_THUNK_DATA itd;
	IMAGE_BASE_RELOCATION ibr;
	IMAGE_BASE_RELOCATION ibr2;
	IMAGE_EXPORT_DIRECTORY ied;
	IMAGE_IMPORT_DESCRIPTOR iid2;


	//string FileName;
	//cin >> FileName;
	string FileName = "C:\\Users\\86134\\source\\repos\\addcalcu\\x64\\Debug\\addcalcu.exe";

	//PathFileExistsA(FileName.c_str());	// 检查文件是否存在

	PETamper pt(FileName);

	HANDLE hpFile = CreateFileA("TestFile", GENERIC_READ | GENERIC_WRITE, 0, NULL, CREATE_ALWAYS, FILE_ATTRIBUTE_NORMAL, NULL);
	if (hpFile == INVALID_HANDLE_VALUE)
	{
		std::cerr << "CreateFile failed with error code " << GetLastError() << std::endl;
		return 1;
	}
	//pt.RawSizeNRawAddressAdjust();
	pt.Assembly(hpFile);

	CloseHandle(hpFile);	// 关闭文件句柄





	
	return 0;
}