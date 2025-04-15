#include"fh.h"   
#include"funcs.cpp"

using namespace std;



int main()
{
	
	//IMAGE_SECTION_HEADER ish;
	IMAGE_IMPORT_DESCRIPTOR iid;	//����������
	IMAGE_IMPORT_BY_NAME iibn;		
	IMAGE_THUNK_DATA itd;
	IMAGE_BASE_RELOCATION ibr;
	IMAGE_BASE_RELOCATION ibr2;
	IMAGE_EXPORT_DIRECTORY ied;
	IMAGE_IMPORT_DESCRIPTOR iid2;


	//string FileName;
	//cin >> FileName;

	// Ӳ�����ļ�·����ԭ�������û����룩
	string FileName = "C:\\Users\\86134\\source\\repos\\addcalcu\\x64\\Debug\\addcalcu.exe";

	unsigned long NumberOfBytesRead;	// ��ȡ�ֽ�������
	unsigned char MZSignal[2];			// ���ڼ��"MZ"ǩ���Ļ�����

	// ��PE�ļ�
	HANDLE hFile = CreateFileA(
		 (LPCSTR)FileName.c_str(),		// �ļ�·��
		 GENERIC_READ | GENERIC_WRITE,	// ��дȨ��
		  0, 							// ������
		  NULL, 						// Ĭ�ϰ�ȫ����
		  OPEN_EXISTING, 				// �������ļ�
		  FILE_ATTRIBUTE_NORMAL, 		// ��ͨ�ļ�
		  NULL);						// ��ģ���ļ�

	// ���仺�����洢�����ļ����� 
	char* allbuffer = new char[GetFileSize(hFile, NULL)];

	// �������ļ������ڴ�
	if (!ReadFile(hFile, allbuffer, GetFileSize(hFile, NULL), &NumberOfBytesRead, NULL))
	{
		cout << "ReadFile failed at ALL!" << endl;
		cout << "GetLastError: " << GetLastError() << endl;
		return 0;
	}

	// ����һ�������ļ���д��PE���ݣ����ڵ���/������
	HANDLE hpFile = CreateFileA("TestFile", GENERIC_READ | GENERIC_WRITE, 0, NULL, CREATE_ALWAYS, FILE_ATTRIBUTE_NORMAL, NULL);
	WriteFile(hpFile, allbuffer, GetFileSize(hFile, NULL), &NumberOfBytesRead, NULL);
	delete[] allbuffer;
	//cout << hFile << endl;

	// ����ļ���ͷMZ��־
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
	
	// ��ȡDOSͷ
	SetFilePointer(hFile,0,NULL,0);
	if (!ReadFile(hFile, &idh, sizeof(IMAGE_DOS_HEADER), &NumberOfBytesRead, NULL))
	{
		cout << "ReadFile failed at IMAGE_DOS_HEADER!" << endl;
		cout << "GetLastError: " << GetLastError() << endl;
		return 0;
	}

	// ��ȡNTͷ��PEǩ����ͷ��Ϣ��
    // e_lfanew�Ǵ�DOSͷ��PEǩ����ƫ����
	SetFilePointer(hFile, idh.e_lfanew, NULL, 0);
	if (!ReadFile(hFile, &inh, sizeof(IMAGE_NT_HEADERS), &NumberOfBytesRead, NULL))
	{
		cout << "ReadFile failed at IMAGE_NT_HEADERS!" << endl;
		cout << "GetLastError: " << GetLastError() << endl;
		return 0;
	}
	
	// ���ļ�ͷ��ȡ��������
	NumberOfSections = inh.FileHeader.NumberOfSections;
	SectionHeaders.resize(NumberOfSections);
	SectionNames.resize(NumberOfSections);
	// �������ͷ��λ�ã�
    // DOSͷ + PEǩ��(4�ֽ�) + �ļ�ͷ(20�ֽ�) + ��ѡͷ��С
	SetFilePointer(hFile, idh.e_lfanew + sizeof(DWORD) + sizeof(IMAGE_FILE_HEADER) + inh.FileHeader.SizeOfOptionalHeader, NULL, 0);
	
	// ��ȡ���н���ͷ��Ϣ
	for (WORD i = 0; i < NumberOfSections; i++)
	{
		if (!ReadFile(hFile, &SectionHeaders[i], sizeof(IMAGE_SECTION_HEADER), &NumberOfBytesRead, NULL))
		{
			cout << "ReadFile failed at SectionHeaders " << i << endl;
			cout << "GetLastError: " << GetLastError() << endl;
			return 0;
		}

		// ��ӡ�������ƣ�8�ֽ���null�����ַ�����
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