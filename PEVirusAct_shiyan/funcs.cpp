#include"fh.h"
using namespace std;

bool EntryPointCover(HANDLE hpFile, DWORD EntryPoint)
{
	unsigned long NumberOfBytesRead;
	SetFilePointer(hpFile, inh.OptionalHeader.AddressOfEntryPoint, NULL, 0);
	WriteFile(hpFile, &EntryPoint, sizeof(EntryPoint), &NumberOfBytesRead, NULL);
	if (GetLastError() != ERROR_SUCCESS)
	{
		std::cout << "ERROR:  " << GetLastError() << endl;
		return false;
	}
	else
		return true;
}

bool SectionTamper(HANDLE hpFile, LONG Point, unsigned char* buffer)
{
	unsigned long NumberOfBytesRead;
	SetFilePointer(hpFile, Point , NULL, 0);
	WriteFile(hpFile, buffer, sizeof(buffer), &NumberOfBytesRead, NULL);
	if (GetLastError() != ERROR_SUCCESS)
	{
		std::cout << "ERROR:  " << GetLastError() << endl;
		return false;
	}
	else
		return true;
	
}

bool TextSectionTamper(HANDLE hpFile, unsigned char* buffer, DWORD EntryPoint)
{
	unsigned long NumberOfBytesRead;
	DWORD PointerToRawPointer;
	for (WORD i = 0; i < NumberOfSections; i++)
	{
		if (!strcmp((char*)SectionNames[i], ".text"))
		{
			SectionTamper(hpFile, SectionHeaders[i].PointerToRawData, buffer);
			EntryPointCover(hpFile, &inh, EntryPoint);
			return true;
		}
	}
	return false;
}

bool FileHeaderTamper(PVOID PEStruct,unsigned char* buffer,int size)
{
	/*
	1 : IMAGE_DOS_HEADER
	2 : IMAGE_NT_HEADERS
	
	
	
	
	
	
	
	
	
	
	*/
	int operation;
	switch(operation)
	{
	case 1:			//IMAGE_DOS_HEADER

		break;


	}
}