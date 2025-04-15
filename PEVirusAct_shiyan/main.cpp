#include"fh.h"

using namespace std;

int main()
{
	IMAGE_DOS_HEADER idh;
	IMAGE_NT_HEADERS inh;
	IMAGE_SECTION_HEADER ish;
	IMAGE_IMPORT_DESCRIPTOR iid;
	IMAGE_IMPORT_BY_NAME iibn;
	IMAGE_THUNK_DATA itd;
	IMAGE_BASE_RELOCATION ibr;
	IMAGE_BASE_RELOCATION ibr2;
	IMAGE_EXPORT_DIRECTORY ied;
	IMAGE_IMPORT_DESCRIPTOR iid2;


	//string FileName;
	//cin >> FileName;
	string FileName = "C:\\Users\\86134\\source\\repos\\addcalcu\\x64\\Debug\\addcalcu.exe";

	unsigned long NumberOfBytesRead;
	unsigned char MZSignal[2];
	HANDLE hFile = CreateFileA((LPCSTR)FileName.c_str(), GENERIC_READ | GENERIC_WRITE, 0, NULL, OPEN_EXISTING, FILE_ATTRIBUTE_NORMAL, NULL);
	ReadFile(hFile, MZSignal, sizeof(MZSignal), &NumberOfBytesRead, NULL);
	if (MZSignal[0] != 'M' || MZSignal[1] != 'Z')
	{
		cout << "This is not a PE file!" << endl;
		return 0;
	}
	_LARGE_INTEGER FilePointer;
	//FilePointer.
	SetFilePointer(hFile,0,NULL,0);
	ReadFile(hFile, &idh, sizeof(IMAGE_DOS_HEADER), &NumberOfBytesRead, NULL);
	SetFilePointer(hFile, idh.e_lfanew, NULL, 0);
	ReadFile(hFile, &inh, sizeof(IMAGE_NT_HEADERS), &NumberOfBytesRead, NULL);
	SetFilePointer(hFile, idh.e_lfanew + sizeof(DWORD) + sizeof(IMAGE_FILE_HEADER) + inh.FileHeader.SizeOfOptionalHeader, NULL, 0);
	ReadFile(hFile, &ish, sizeof(IMAGE_SECTION_HEADER), &NumberOfBytesRead, NULL);
	
	WORD NumberOfSections = inh.FileHeader.NumberOfSections;


	/*
	for (int i = 0; i < sizeof(IMAGE_DOS_HEADER); i++)
	{
		cout << hex << (int)((unsigned char*)&idh)[i] << " ";
	}
	*/
	
	
	return 0;
}