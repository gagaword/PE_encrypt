#include<iostream>
#include<Windows.h>
#include "ReadFileMeory.h"
#include "AddOriginDataToShell.h"

#pragma   comment(linker,"/subsystem:\"windows\"  /entry:\"mainCRTStartup\""   ) 

using namespace std;

#define SHELL_FILE_NAME "D:\\source\\repos\\Shell\\Release\\Shell.exe"  //壳子名
#define ORGIN_FILE_NAME "C:\\Users\\GaGa\\Desktop\\Process.exe"  //要被加壳的程序名称

int main(int argc, char* argv[])
{
	FILE_INFO OriginFile;
	FILE_INFO ShellFile;
	ReadFileMeory::ReadOriginFileMoery(ORGIN_FILE_NAME, &OriginFile);
	ReadFileMeory::ReadOriginFileMoery(SHELL_FILE_NAME, &ShellFile);

	AddOriginDataToShell::addOriginToShell(&OriginFile, &ShellFile);

	return 0;
}
