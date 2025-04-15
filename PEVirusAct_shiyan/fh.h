#pragma once
#include<iostream>
#include<windows.h>
#include<fileapi.h>
#include<vector>

//using namespace std;

IMAGE_DOS_HEADER idh;           //DOS头（以"MZ"开头）
IMAGE_NT_HEADERS inh;			//NT头（PE签名、文件头、可选头）

WORD NumberOfSections;

std::vector<IMAGE_SECTION_HEADER> SectionHeaders;
std::vector<BYTE[8]> SectionNames;

bool FileHeaderTamper;
bool SectionTamper(HANDLE, LONG, unsigned char*);
bool TextSectionTamper(HANDLE, IMAGE_SECTION_HEADER, unsigned char*, int);
bool EntryPointCover(HANDLE, IMAGE_NT_HEADERS*, DWORD);

unsigned char shellcode[];

