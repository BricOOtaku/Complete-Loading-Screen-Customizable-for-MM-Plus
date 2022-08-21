#include <Windows.h>
#include <sstream>
#include <string>

#include "detours.h"
#include "Helpers.h"
#include "Signature.h"
#include "toml.hpp"

int rnd;
int rnd2;
char rorn = 'r';

int randomLoading = 1;
int loadingStyle = -1;
toml::table config;

//1.0.2 0x140CC2138
SIG_SCAN ( sigLoadingBg, "\x6C\x6F\x61\x64\x69\x6E\x67\x5F\x62\x67\x00\x00\x00\x00\x00\x00", "xxxxxxxxxx??????" )

//1.0.2 0x140CC2198
SIG_SCAN(sigNowLoading, "\x6E\x6F\x77\x5F\x6C\x6F\x61\x64\x69\x6E\x67\x00\x00\x00\x00\x00", "xxxxxxxxxxx?????")

//1.0.2 0x140653FC0
SIG_SCAN(sigLoadingScreen, "\x48\x89\x5C\x24\x00\x48\x89\x7C\x24\x00\x55\x48\x8D\xAC\x24\x00\x00\x00\x00\x48\x81\xEC\x00\x00\x00\x00\x48\x8B\x05\x00\x00\x00\x00\x48\x33\xC4\x48\x89\x85\x00\x00\x00\x00\x48\x8B\xF9\x45\x33\xC0\x41\x8D\x50\x04\x33\xC9\xE8\x00\x00\x00\x00\x8B\xD8\x48\x8D\x15\x00\x00\x00\x00", "xxxx?xxxx?xxxxx????xxx????xxx????xxxxxx????xxxxxxxxxxxxx????xxxxx????")

void load_bg(unsigned char v1, unsigned char v2, unsigned char v3, unsigned char v4)
{
	unsigned char zeroX = '0x0';
	std::stringstream sstream;
	sstream << std::hex << v1;
	sstream << std::hex << v2;
	sstream << std::hex << v3;
	sstream << std::hex << v4;
	std::string result = sstream.str();
	unsigned char V1 = zeroX + v1;
	unsigned char V2 = zeroX + v2;
	unsigned char V3 = zeroX + v3;
	unsigned char V4 = zeroX + v4;
	WRITE_MEMORY((char*)sigLoadingBg()+0x04, uint8_t, 'b', 'g', V1, V2, V3, V4);
}

void random_bg()
{
	rnd = rand() % randomLoading;
	
	int first = rnd / 1000;
	rnd = rnd % 1000;
	int second = rnd / 100;
	rnd = rnd % 100;
	int third = rnd / 10;
	rnd = rnd % 10;
	int fourth = rnd;
	load_bg(first, second, third, fourth);
}

void set_load_style(int x1)
{
	switch (x1) 
	{
	case 1: //X
		WRITE_MEMORY(sigNowLoading(), uint8_t, 'p', 'j', 'x');
		break;

	case 2: //FT
		WRITE_MEMORY(sigNowLoading(), uint8_t, 'p', 'f', 't');
		break;

	case 3: //F2nd
		WRITE_MEMORY(sigNowLoading(), uint8_t, 'd', 'f', '2');
		break;

	case 4: //F
		WRITE_MEMORY(sigNowLoading(), uint8_t, 'p', 'j', 'f');
		break;

	case 5: //EX
		WRITE_MEMORY(sigNowLoading(), uint8_t, 'p', 'e', 'x');
		break;

	case 6: //2nd
		WRITE_MEMORY(sigNowLoading(), uint8_t, 'p', 'j', 'd');
		break;

	default: //M39's
		rorn = 'r';
		WRITE_MEMORY(sigNowLoading(), uint8_t, 'n', 'o', 'w');
		break;
	}

	if (x1 != 0)
	{
		rorn = 'n';
	}
}

void random_load()
{
	rnd2 = (rand() % 7);
	set_load_style(rnd2);
}

HOOK(__int64, __fastcall, _LoadingScreen, sigLoadingScreen(), int a1)
{
	original_LoadingScreen(a1);
	random_bg();
	if (loadingStyle == -1) //Set to Random
	{
		random_load();
	}
	return 0;
}

extern "C" __declspec(dllexport) void Init()
{
	printf("[Complete Loading Screen Customizable for MM+] Initializing...\n");
	try
	{
		config = toml::parse_file("config.toml");
		try
		{
			randomLoading = config["Random_Loading"].value_or(0);
			loadingStyle = config["Loading_Style"].value_or(0);
		}
		catch (std::exception& exception)
		{
			char text[1024];
			sprintf_s(text, "Failed to parse config.toml:\n%s", exception.what());
			MessageBoxA(nullptr, text, "Complete Loading Screen Customizable for MM+", MB_OK | MB_ICONERROR);
		}
	}
	catch (std::exception& exception)
	{
		char text[1024];
		sprintf_s(text, "Failed to parse config.toml:\n%s", exception.what());
		MessageBoxA(nullptr, text, "Complete Loading Screen Customizable for MM+", MB_OK | MB_ICONERROR);
	}

	if (randomLoading < 1)
	{
		randomLoading = 1;
	}
	else if (randomLoading > 1023)
	{
		randomLoading = 1023;
	}

	srand(time(NULL));

	random_bg();

	if (loadingStyle != -1)
	{
		set_load_style(loadingStyle);
	}

	INSTALL_HOOK(_LoadingScreen);
}


BOOL APIENTRY DllMain(HMODULE hModule, DWORD  ul_reason_for_call, LPVOID lpReserved)
{
	switch (ul_reason_for_call)
	{
	case DLL_PROCESS_ATTACH:
	case DLL_THREAD_ATTACH:
	case DLL_THREAD_DETACH:
	case DLL_PROCESS_DETACH:
		break;
	}
	return TRUE;
}
