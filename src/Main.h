#pragma once
#pragma once

#include <Windows.h>
#include <gdiplus.h>
#include <CommCtrl.h>
#pragma comment(lib,"comctl32.lib")

#include <string>
#include <vector>

#include "resource.h"

#include "Helpers.h"
//#include "Decryptor.h"
#include "Decryptor_v1.h"

#define IDC_PICTURE_BOX 102
#define IDC_FILE_BOX 103
#define IDC_FILE_BUTTON 104
#define IDC_WORK_BUTTON 105
#define IDC_STATUS_BOX 106
#define IDC_QUIT_BUTTON 107
#define IDC_ABOUT_BUTTON 108
#define IDC_PROGRESSBAR 110

LRESULT __stdcall WndCallback(HWND hwnd, UINT Message, WPARAM wParam, LPARAM lParam);

void UpdateStatusBox(const std::string& msg);
void UpdateFileBox(const std::string& filepath);
void SetProgressBarRange(int min_, int max_, int step);
void ProgressProgressBar(int progress);

typedef void (*SetProgressBarRange_t)(int min_, int max_, int step);
typedef void (*ProgressProgressBar_t)(int progress);

void LocateFile(void);
DWORD __stdcall Work(LPVOID lpParameter);
DWORD __stdcall TimerIdle(LPVOID lpParameter);

static HINSTANCE sInstance;
static std::string sClassName;
static std::string sWindowName;
static HWND sWindowHandle;

static std::string sFilename;

static HWND pictureBoxHandle, fileBoxHandle, fileButtonHandle, workButtonHandle, statusBoxHandle, quitButtonHandle, aboutButtonHandle, progressBarHandle;

extern SetProgressBarRange_t pfnSetProgressBarRange;
extern ProgressProgressBar_t pfnProgressProgressBar;