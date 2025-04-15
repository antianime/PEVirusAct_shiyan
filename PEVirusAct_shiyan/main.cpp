#include"fh.h"   
#include"funcs.cpp"

using namespace std;



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

	// 硬编码文件路径（原代码有用户输入）
	string FileName = "C:\\Users\\86134\\source\\repos\\addcalcu\\x64\\Debug\\addcalcu.exe";

	unsigned long NumberOfBytesRead;	// 读取字节数计数
	unsigned char MZSignal[2];			// 用于检查"MZ"签名的缓冲区

	// 打开PE文件
	HANDLE hFile = CreateFileA(
		 (LPCSTR)FileName.c_str(),		// 文件路径
		 GENERIC_READ | GENERIC_WRITE,	// 读写权限
		  0, 							// 不共享
		  NULL, 						// 默认安全属性
		  OPEN_EXISTING, 				// 打开已有文件
		  FILE_ATTRIBUTE_NORMAL, 		// 普通文件
		  NULL);						// 无模板文件

	// 分配缓冲区存储整个文件内容 
	char* allbuffer = new char[GetFileSize(hFile, NULL)];

	// 将整个文件读入内存
	if (!ReadFile(hFile, allbuffer, GetFileSize(hFile, NULL), &NumberOfBytesRead, NULL))
	{
		cout << "ReadFile failed at ALL!" << endl;
		cout << "GetLastError: " << GetLastError() << endl;
		return 0;
	}

	// 创建一个测试文件并写入PE内容（用于调试/分析）
	HANDLE hpFile = CreateFileA("TestFile", GENERIC_READ | GENERIC_WRITE, 0, NULL, CREATE_ALWAYS, FILE_ATTRIBUTE_NORMAL, NULL);
	WriteFile(hpFile, allbuffer, GetFileSize(hFile, NULL), &NumberOfBytesRead, NULL);
	delete[] allbuffer;
	//cout << hFile << endl;

	// 检查文件开头MZ标志
	SetFilePointer(hFile, 0, NULL, 0);
	if (!ReadFile(hFile, MZSignal, sizeof(MZSignal), &NumberOfBytesRead, NULL))
	{
		cout << "ReadFile failed at MZSignal!" << endl;
		cout << "GetLastError: " << GetLastError() << endl;
		return 0;
	}
	if (MZSignal[0] != 'M' || MZSignal[1] != 'Z')
	{
		cout << "This is not a PE file!" << endl;
		cout << "GetLastError: " << GetLastError() << endl;
		return 0;
	}
	
	// 读取DOS头
	SetFilePointer(hFile,0,NULL,0);
	if (!ReadFile(hFile, &idh, sizeof(IMAGE_DOS_HEADER), &NumberOfBytesRead, NULL))
	{
		cout << "ReadFile failed at IMAGE_DOS_HEADER!" << endl;
		cout << "GetLastError: " << GetLastError() << endl;
		return 0;
	}

	// 读取NT头（PE签名和头信息）
    // e_lfanew是从DOS头到PE签名的偏移量
	SetFilePointer(hFile, idh.e_lfanew, NULL, 0);
	if (!ReadFile(hFile, &inh, sizeof(IMAGE_NT_HEADERS), &NumberOfBytesRead, NULL))
	{
		cout << "ReadFile failed at IMAGE_NT_HEADERS!" << endl;
		cout << "GetLastError: " << GetLastError() << endl;
		return 0;
	}
	
	// 从文件头获取节区数量
	NumberOfSections = inh.FileHeader.NumberOfSections;
	SectionHeaders.resize(NumberOfSections);
	SectionNames.resize(NumberOfSections);
	// 计算节区头的位置：
    // DOS头 + PE签名(4字节) + 文件头(20字节) + 可选头大小
	SetFilePointer(hFile, idh.e_lfanew + sizeof(DWORD) + sizeof(IMAGE_FILE_HEADER) + inh.FileHeader.SizeOfOptionalHeader, NULL, 0);
	
	// 读取所有节区头信息
	for (WORD i = 0; i < NumberOfSections; i++)
	{
		if (!ReadFile(hFile, &SectionHeaders[i], sizeof(IMAGE_SECTION_HEADER), &NumberOfBytesRead, NULL))
		{
			cout << "ReadFile failed at SectionHeaders " << i << endl;
			cout << "GetLastError: " << GetLastError() << endl;
			return 0;
		}

		// 打印节区名称（8字节以null填充的字符串）
		cout << "Section Name: ";
		for (int j = 0; j < 8; j++)
		{
			SectionNames[i][j] = SectionHeaders[i].Name[j];
			cout << SectionNames[i][j];
		}
		cout << endl;
		
	}
	
		
	



	/*
	for (int i = 0; i < sizeof(IMAGE_DOS_HEADER); i++)
	{
		cout << hex << (int)((unsigned char*)&idh)[i] << " ";
	}
	*/
	
	
	return 0;
}