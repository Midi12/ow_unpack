#include "Main.h"

SetProgressBarRange_t pfnSetProgressBarRange;
ProgressProgressBar_t pfnProgressProgressBar;

int __stdcall WinMain(HINSTANCE hInstance, HINSTANCE hPrevInstance, LPSTR lpCmdLine, int nCmdShow)
{
	WNDCLASSEX windowClass = { 0 };
	windowClass.cbSize = sizeof(WNDCLASSEX);

	sInstance = hInstance;
	sClassName = "ow_unpack";
	sWindowName = "ow_unpack v1.2";

	if (!GetClassInfoEx(sInstance, sClassName.c_str(), &windowClass))
	{
		windowClass.style = CS_HREDRAW | CS_VREDRAW;
		windowClass.lpfnWndProc = WndCallback;
		windowClass.cbClsExtra = 0;
		windowClass.cbWndExtra = 0;
		windowClass.hInstance = sInstance;
		windowClass.hIcon = LoadIcon(sInstance, MAKEINTRESOURCE(IDI_ICON1));
		windowClass.hCursor = LoadCursor(nullptr, IDC_ARROW);
		windowClass.hbrBackground = (HBRUSH)GetStockObject(WHITE_BRUSH);
		windowClass.lpszMenuName = nullptr;
		windowClass.lpszClassName = sClassName.c_str();
		windowClass.hIconSm = LoadIcon(sInstance, MAKEINTRESOURCE(IDI_ICON1));

		if (!RegisterClassEx(&windowClass))
		{
			MessageBox(nullptr, "Cannot register window", sWindowName.c_str(), MB_OK | MB_ICONERROR);
			return EXIT_FAILURE;
		}
	}

	sWindowHandle = CreateWindowEx(	WS_EX_STATICEDGE,
									sClassName.c_str(),
									sWindowName.c_str(),
									WS_OVERLAPPEDWINDOW,
									CW_USEDEFAULT,
									CW_USEDEFAULT,
									402,
									232,
									nullptr,
									nullptr,
									sInstance,
									nullptr);

	if (!sWindowHandle)
	{
		MessageBox(nullptr, "Cannot create window", sWindowName.c_str(), MB_OK | MB_ICONERROR);
		return EXIT_FAILURE;
	}

	SetWindowLong(sWindowHandle, GWL_STYLE, WS_POPUP | WS_MINIMIZEBOX);

	pfnSetProgressBarRange = SetProgressBarRange;
	pfnProgressProgressBar = ProgressProgressBar;

	ShowWindow(sWindowHandle, SW_SHOW);
	UpdateWindow(sWindowHandle);

	MSG msg;
	while (GetMessage(&msg, nullptr, NULL, NULL))
	{
		TranslateMessage(&msg);
		DispatchMessage(&msg);
	}

	return msg.wParam;
}

LRESULT __stdcall WndCallback(HWND hwnd, UINT Message, WPARAM wParam, LPARAM lParam)
{
	HBITMAP splashHandle;

	switch (Message)
	{
	case WM_CREATE:
		InitCommonControls();
		pictureBoxHandle = CreateWindowEx(	NULL,
											"Static",
											nullptr,
											WS_CHILD | WS_VISIBLE | SS_BITMAP,
											1,
											1,
											400,
											150,
											hwnd,
											(HMENU)IDC_PICTURE_BOX,
											sInstance,
											nullptr);

		splashHandle = (HBITMAP)LoadImage(sInstance, MAKEINTRESOURCE(IDB_BITMAP1), IMAGE_BITMAP, 0, 0, NULL);
		SendMessage(pictureBoxHandle, STM_SETIMAGE, (WPARAM)IMAGE_BITMAP, (LPARAM)splashHandle);

		fileBoxHandle = CreateWindowEx(	NULL,
										"Edit",
										"No file selected",
										WS_BORDER | WS_CHILD | WS_VISIBLE | ES_READONLY,
										0,
										152,
										250,
										25,
										hwnd,
										(HMENU)IDC_FILE_BOX,
										sInstance,
										nullptr);

		fileButtonHandle = CreateWindowEx(	NULL,
											"Button",
											"file",
											WS_BORDER | WS_CHILD | WS_VISIBLE | BS_PUSHBUTTON | BS_FLAT,
											250,
											152,
											75,
											25,
											hwnd,
											(HMENU)IDC_FILE_BUTTON,
											sInstance,
											nullptr);

		workButtonHandle = CreateWindowEx(	NULL,
											"Button",
											"decrypt",
											WS_BORDER | WS_CHILD | WS_VISIBLE | BS_PUSHBUTTON | BS_FLAT,
											325,
											152,
											75,
											25,
											hwnd,
											(HMENU)IDC_WORK_BUTTON,
											sInstance,
											nullptr);

		statusBoxHandle = CreateWindowEx(	NULL,
											"Edit",
											"Idle",
											WS_BORDER | WS_CHILD | WS_VISIBLE | ES_READONLY,
											0,
											178,
											400,
											25,
											hwnd,
											(HMENU)IDC_STATUS_BOX,
											sInstance,
											nullptr);

		quitButtonHandle = CreateWindowEx(	NULL,
											"Button",
											"x",
											WS_BORDER | WS_CHILD | WS_VISIBLE | BS_PUSHBUTTON | BS_FLAT,
											380,
											1,
											20,
											20,
											hwnd,
											(HMENU)IDC_QUIT_BUTTON,
											sInstance,
											nullptr);

		aboutButtonHandle = CreateWindowEx(	NULL,
											"Button",
											"?",
											WS_BORDER | WS_CHILD | WS_VISIBLE | BS_PUSHBUTTON | BS_FLAT,
											360,
											1,
											20,
											20,
											hwnd,
											(HMENU)IDC_ABOUT_BUTTON,
											sInstance,
											nullptr);

		progressBarHandle = CreateWindowEx(	NULL,
											PROGRESS_CLASS,
											nullptr,
											WS_CHILD | WS_VISIBLE | PBS_SMOOTH,
											0,
											205,
											400,
											25,
											hwnd,
											(HMENU)IDC_PROGRESSBAR,
											sInstance,
											nullptr);
		break;
	case WM_COMMAND:
		switch (LOWORD(wParam))
		{
		case IDC_PICTURE_BOX:
			break;
		case IDC_FILE_BOX:
			break;
		case IDC_FILE_BUTTON:
			LocateFile();
			break;
		case IDC_WORK_BUTTON:
			CreateThread(nullptr, 0, Work, (LPVOID)sFilename.c_str(), NULL, nullptr);
			break;
		case IDC_STATUS_BOX:
			break;
		case IDC_QUIT_BUTTON:
			PostQuitMessage(0);
			break;
		case IDC_ABOUT_BUTTON:
			MessageBox(nullptr, "ow_unpack - an unpacker/decryptor for Blizzard's Overwatch Game\n\nCode by Midi12\nArt by Extasy Hosting", sWindowName.c_str(), MB_OK);
			break;
		default:
			break;
		}
		break;
	case WM_CTLCOLORSTATIC:
		if ((HWND)lParam == pictureBoxHandle || (HWND)lParam == quitButtonHandle)
		{
			HDC hdc = (HDC)wParam;
			SetBkMode(hdc, TRANSPARENT);
			return (LRESULT)GetStockObject(HOLLOW_BRUSH);
		}
		break;
	case WM_NCHITTEST:
	{
		LRESULT hit = DefWindowProc(hwnd, Message, wParam, lParam);
		if (hit == HTCLIENT) hit = HTCAPTION;
		return hit;
	}
		break;
	case WM_CLOSE:
		DestroyWindow(hwnd);
		break;
	case WM_DESTROY:
		PostQuitMessage(0);
		break;
	default:
		LRESULT res = DefWindowProc(hwnd, Message, wParam, lParam);
		HideCaret(fileBoxHandle);
		HideCaret(statusBoxHandle);
		return res;
		break;
	}

	return 0;
}

void UpdateStatusBox(const std::string& msg)
{
	SetWindowText(statusBoxHandle, msg.c_str());
}

void UpdateFileBox(const std::string& filepath)
{
	SetWindowText(fileBoxHandle, filepath.c_str());
}

void LocateFile(void)
{
	OPENFILENAME ofn = { 0 };
	ofn.lStructSize = sizeof(OPENFILENAME);

	char filepath[MAX_PATH] = "";

	ofn.hwndOwner = fileBoxHandle;
	ofn.lpstrFilter = "Overwatch.exe\0Overwatch.exe\0All Files(*.*)\0*.*\0";
	ofn.lpstrFile = filepath;
	ofn.nMaxFile = MAX_PATH;
	ofn.Flags = OFN_EXPLORER | OFN_FILEMUSTEXIST;
	ofn.lpstrDefExt = "exe";

	if (GetOpenFileName(&ofn))
	{
		sFilename = ofn.lpstrFile;
		
		char *shortName = nullptr;
		int len = GetShortPathName(ofn.lpstrFile, nullptr, 0);

		if (len != 0)
		{
			shortName = new char[len];
			GetShortPathName(ofn.lpstrFile, shortName, len);
			UpdateFileBox(shortName);
			delete[] shortName;
		}
		else
		{
			UpdateFileBox(ofn.lpstrFile);
		}
	}
	else
	{
		sFilename = "";
		UpdateFileBox("No file selected");
	}
}

DWORD __stdcall Work(LPVOID lpParameter)
{
	std::string filepath = (char *)lpParameter;

	std::vector<std::uint8_t> fileBuffer;

	if (!helpers::ReadFileToBuffer(filepath, fileBuffer))
	{
		UpdateStatusBox("Cannot open " + filepath);
		return -1;
	}

	XorTable xtbl;

	UpdateStatusBox("Renaming .text\\0\\f\\0 fake section to .packer ...");
	decryptor_v1::RenameFakeTextSection(fileBuffer);

	UpdateStatusBox("Gathering necessary data ...");
	decryptor_v1::GatherData(fileBuffer, xtbl);

	UpdateStatusBox("Decrypting & fixing imports ...");
	decryptor_v1::DecryptHeader(fileBuffer, xtbl);

	UpdateStatusBox("Decrypting .text section ...");
	decryptor_v1::DecryptTextSection(fileBuffer, xtbl);

	UpdateStatusBox("Removing obfuscation layer ...");
	decryptor_v1::RemoveObfuscationLayer(fileBuffer);
	
	SetProgressBarRange(0, 100, 10);

	UpdateStatusBox("Writing file to disk ...");
	std::string ext = filepath.substr(filepath.rfind('.'));
	std::ofstream out(filepath.substr(0, filepath.rfind('.')) + ".clean" + ext, std::ios::binary | std::ios::trunc);
	if (!out.good())
	{
		UpdateStatusBox("Cannot create " + filepath.substr(0, filepath.rfind('.')) + ".clean" + ext);
		return -1;
	}

	ProgressProgressBar(33);
	std::copy(fileBuffer.begin(), fileBuffer.end(), std::ostreambuf_iterator<char>(out));
	ProgressProgressBar(66);

	if (out.fail())
	{
		UpdateStatusBox("Cannot write buffer to disk");
		return -1;
	}

	ProgressProgressBar(100);
	UpdateStatusBox("Done :)");

	CreateThread(nullptr, 0, TimerIdle, nullptr, 0, nullptr);

	return 0;
}

DWORD __stdcall TimerIdle(LPVOID lpParameter)
{
	Sleep(5000);
	UpdateStatusBox("Idle");
	SetProgressBarRange(0, 100, 10);
	ProgressProgressBar(0);
	return 0;
}

void SetProgressBarRange(int min_, int max_, int step)
{
	SendMessage(progressBarHandle, PBM_SETRANGE, 0, MAKELPARAM(min_, max_));
	SendMessage(progressBarHandle, PBM_SETSTEP, (WPARAM)step, 0);
}

void ProgressProgressBar(int progress)
{
	SendMessage(progressBarHandle, PBM_SETPOS, progress, 0);
}