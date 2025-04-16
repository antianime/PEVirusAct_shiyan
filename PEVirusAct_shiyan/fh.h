#pragma once            // ��ֹͷ�ļ����ظ�����

#include<iostream>
#include<windows.h>     // Windows APIͷ�ļ�
#include<fileapi.h>     // �ļ�����API
#include<vector>        // STL��������

//#include <iomanip>//�����������

using namespace std;

//FileHeaderTamper : Object
#define DOS_T 1     // DOSͷ�۸�
#define NT_T 2      // NTͷ�۸�

//FileHeaderTamper : DOS - Decision
//#define 

//FileHeaderTamper : NT - Decision
#define e_magic_T 1     // �޸�PEǩ��
#define e_lfanew_T 2    // �޸�ָ��PEͷ��ƫ����


// �ֶ���Ϣ�ṹ��
typedef struct FieldInfo
{
    std::string field;  // �ֶ�����
    int size;           // �ֶδ�С(�ֽ�)
    int offset;         // �ֶ�ƫ����
}FieldInfo;

//std::vector< FieldInfo>IMAGE_DOS_HEADER_INFO;

//std::vector<std::tuple<std::string, int, int>>IMAGE_DOS_HEADER_INFO[19];
//std::vector<std::tuple<std::string, int, int>>IMAGE_NT_HEADER_INFOS[];


// DOS����ṹ�壨64�ֽڣ�
typedef struct IMAGE_DOS_STUB
{
    BYTE stub[64];      // DOS�������
}IMAGE_DOS_STUB;


//RICH_HEADER;
//extern char* stubbuffer;
extern std::vector<std::vector<FieldInfo>>ALL_HEADER_INFO;
extern std::vector< FieldInfo>IMAGE_DOS_HEADER_INFO;


/*

// �ⲿ��������
extern std::vector<BYTE> stubbuffer;    // DOS���������
extern IMAGE_DOS_HEADER idh;           //DOSͷ����"MZ"��ͷ��
extern IMAGE_NT_HEADERS inh;			//NTͷ��PEǩ�����ļ�ͷ����ѡͷ��

extern WORD NumberOfSections;           // ��������
extern std::vector<IMAGE_SECTION_HEADER> SectionHeaders;    // ����ͷ����
extern std::vector<std::vector<BYTE>>SectionNames;          // ������������
extern std::vector < std::vector<char>>Sections;            // ������������

*/



// ��������
bool FileHeaderTamper();        // �ļ�ͷ�۸ĺ���
bool SectionTamper(HANDLE, LONG, unsigned char*);       // �����۸�
bool TextSectionTamper(HANDLE, unsigned char*, int);    // .text�����۸�
bool EntryPointCover(HANDLE, DWORD);                     // ��ڵ㸲��

bool HeaderInfoIni(std::vector<FieldInfo>);         // ͷ��Ϣ��ʼ��
bool FieldTamper(LONG ,char* );                     // �ֶδ۸�
bool AtomTamper(PVOID , LONG , unsigned char* , int );  //obsolete

bool Assembly(HANDLE);              // �����ع���


extern unsigned char shellcode[];       // �ⲿ�����shellcode����

class PETamper
{
public:
	IMAGE_DOS_HEADER idh;           //DOSͷ����"MZ"��ͷ��
	IMAGE_NT_HEADERS inh;			//NTͷ��PEǩ�����ļ�ͷ����ѡͷ��
	std::vector<BYTE> stubbuffer;						// �洢DOS�������
	// ����������ݽṹ
	WORD NumberOfSections;
	std::vector<IMAGE_SECTION_HEADER> SectionHeaders;	// �洢���н���ͷ
	std::vector<std::vector<BYTE>>SectionNames;			// �洢���н�������
	std::vector<std::vector<BYTE>>Sections;			// �洢���н�������





	PETamper(std::string FileName);
	//~PETamper();
	//bool FileHeaderTamper(HANDLE hFile, unsigned char* buffer, int size, int ObjectFlag, int DecisionFlag);
	bool SectionTamper(HANDLE hFile, LONG Point, unsigned char* buffer);
	bool TextSectionTamper(HANDLE hFile, unsigned char* buffer, DWORD EntryPoint);
	bool EntryPointCover(HANDLE hFile, DWORD EntryPoint);
	//bool HeaderInfoIni(std::vector<FieldInfo> HEADER_INFO);
	bool FieldTamper(PVOID object, LONG Point, char* buffer);
	bool DOSFieldTamper(PVOID object, LONG Point, std::string buffer);
	//bool AtomTamper(PVOID Struct, LONG Point, unsigned char* buffer, int size);  //obsolete

	bool RawSizeNRawAddressAdjust();
	bool DisplaySection();
	bool AllDisplay();

	bool Assembly(HANDLE hpFile);

};