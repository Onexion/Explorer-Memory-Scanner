#include <windows.h>
#include <tlhelp32.h>
#include <psapi.h>
#include <tchar.h>
#include <iostream>
#include <string>
#include <vector>
#include <unordered_set>
#include <algorithm>
#include <cctype>
#include <iomanip>
#include <filesystem>
#include <wincrypt.h>

#pragma comment(lib, "advapi32.lib")

struct HandleWrapper {
    HANDLE handle;
    HandleWrapper(HANDLE h = INVALID_HANDLE_VALUE) : handle(h) {}
    ~HandleWrapper() { if (handle != nullptr && handle != INVALID_HANDLE_VALUE) CloseHandle(handle); }
    operator HANDLE() const { return handle; }
};

bool containsCaseInsensitive(const std::string& haystack, const std::string& needle) {
    return std::search(
        haystack.begin(), haystack.end(),
        needle.begin(), needle.end(),
        [](char ch1, char ch2) {
            return std::tolower(static_cast<unsigned char>(ch1)) ==
                   std::tolower(static_cast<unsigned char>(ch2));
        }
    ) != haystack.end();
}

DWORD findProcessId(const std::string& procName) {
    PROCESSENTRY32 pe32{};
    pe32.dwSize = sizeof(PROCESSENTRY32);
    HandleWrapper hSnapshot(CreateToolhelp32Snapshot(TH32CS_SNAPPROCESS, 0));
    if (hSnapshot.handle == INVALID_HANDLE_VALUE) return 0;

    if (Process32First(hSnapshot, &pe32)) {
        do {
            if (_stricmp(pe32.szExeFile, procName.c_str()) == 0) {
                return pe32.th32ProcessID;
            }
        } while (Process32Next(hSnapshot, &pe32));
    }
    return 0;
}

void scanProcess(DWORD pid, std::vector<std::string>& pcaResults, std::vector<std::string>& explorerResults) {
    HandleWrapper hProc(OpenProcess(PROCESS_VM_READ | PROCESS_QUERY_INFORMATION, FALSE, pid));
    if (!hProc || hProc.handle == INVALID_HANDLE_VALUE) return;

    MEMORY_BASIC_INFORMATION mbi{};
    unsigned char* addr = nullptr;
    const size_t bufSize = 65536;
    std::vector<char> buffer(bufSize);
    std::unordered_set<std::string> seenStrings;

    std::cout << "\rRunning Memory Dump..." << std::flush;

    while (VirtualQueryEx(hProc, addr, &mbi, sizeof(mbi)) == sizeof(mbi)) {
        if (mbi.State == MEM_COMMIT &&
            (mbi.Protect & (PAGE_READWRITE | PAGE_EXECUTE_READ | PAGE_EXECUTE_READWRITE))) {

            unsigned char* region = static_cast<unsigned char*>(mbi.BaseAddress);
            SIZE_T regionSize = mbi.RegionSize;
            SIZE_T offset = 0, bytesRead = 0;

            while (offset < regionSize) {
                SIZE_T toRead = std::min(bufSize, regionSize - offset);

                if (ReadProcessMemory(hProc, region + offset, buffer.data(), toRead, &bytesRead)) {
                    std::string current;
                    for (size_t i = 0; i < bytesRead; i++) {
                        char c = buffer[i];
                        if (isprint(static_cast<unsigned char>(c)) || c=='\\'||c==':'||c=='/'||c=='.'||c=='-'||c=='_'||c==','||c=='!') {
                            current.push_back(c);
                        } else {
                            if (!current.empty()) {
                                bool isPCA = containsCaseInsensitive(current, "trace,");
                                if (isPCA && seenStrings.insert(current).second) {
                                    size_t pathStart = current.find_first_of("ABCDEFGHIJKLMNOPQRSTUVWXYZabcdefghijklmnopqrstuvwxyz");
                                    pathStart = current.find(":\\", pathStart);
                                    if (pathStart != std::string::npos) {
                                        size_t exePos = current.find(".exe", pathStart);
                                        if (exePos != std::string::npos) {
                                            exePos += 4;
                                            std::string path = current.substr(pathStart - 1, exePos - (pathStart - 1));
                                            pcaResults.push_back(path);
                                        }
                                    }
                                } else {
                                    bool isExplorer = containsCaseInsensitive(current, ":\\") && containsCaseInsensitive(current, ".exe");
                                    if (isExplorer && seenStrings.insert(current).second)
                                        explorerResults.push_back(current);
                                }
                                current.clear();
                            }
                        }
                    }
                    if (!current.empty()) {
                        bool isPCA = containsCaseInsensitive(current, "trace,");
                        if (isPCA && seenStrings.insert(current).second) {
                            size_t pathStart = current.find_first_of("ABCDEFGHIJKLMNOPQRSTUVWXYZabcdefghijklmnopqrstuvwxyz");
                            pathStart = current.find(":\\", pathStart);
                            if (pathStart != std::string::npos) {
                                size_t exePos = current.find(".exe", pathStart);
                                if (exePos != std::string::npos) {
                                    exePos += 4;
                                    std::string path = current.substr(pathStart - 1, exePos - (pathStart - 1));
                                    pcaResults.push_back(path);
                                }
                            }
                        } else {
                            bool isExplorer = containsCaseInsensitive(current, ":\\") && containsCaseInsensitive(current, ".exe");
                            if (isExplorer && seenStrings.insert(current).second)
                                explorerResults.push_back(current);
                        }
                    }
                }
                offset += toRead;
            }
        }
        addr += mbi.RegionSize;
    }
    std::cout << "\r" << std::string(40, ' ') << "\r" << std::flush;
}

bool IsFileSigned(const std::wstring& filePath) {
    HCERTSTORE hStore = nullptr;
    HCRYPTMSG hMsg = nullptr;
    DWORD encoding = 0, contentType = 0, formatType = 0;

    BOOL result = CryptQueryObject(
        CERT_QUERY_OBJECT_FILE,
        filePath.c_str(),
        CERT_QUERY_CONTENT_FLAG_PKCS7_SIGNED_EMBED,
        CERT_QUERY_FORMAT_FLAG_BINARY,
        0,
        &encoding,
        &contentType,
        &formatType,
        &hStore,
        &hMsg,
        nullptr);

    if (hStore) CertCloseStore(hStore, 0);
    if (hMsg) CryptMsgClose(hMsg);

    return result == TRUE;
}

void printResults(const std::string& title, const std::vector<std::string>& results) {
    if (results.empty()) return;

    std::cout << "\n" << title << ":\n";
    size_t maxLen = results.empty() ? 0 :
        std::max_element(results.begin(), results.end(),
            [](const std::string& a, const std::string& b) { return a.length() < b.length(); })->length();
    size_t colStart = maxLen + 5;

    HANDLE hConsole = GetStdHandle(STD_OUTPUT_HANDLE);

    CONSOLE_SCREEN_BUFFER_INFO csbi;
    if (GetConsoleScreenBufferInfo(hConsole, &csbi)) {
        SHORT currentWidth = csbi.srWindow.Right - csbi.srWindow.Left + 1;
        size_t neededWidth = colStart + 7 + 3 + 9;
        if (neededWidth > currentWidth) {
            COORD newSize = csbi.dwSize;
            newSize.X = static_cast<SHORT>(neededWidth);
            SetConsoleScreenBufferSize(hConsole, newSize);
            SMALL_RECT newRect = csbi.srWindow;
            newRect.Right = newRect.Left + static_cast<SHORT>(neededWidth) - 1;
            SetConsoleWindowInfo(hConsole, TRUE, &newRect);
        }
    }

    for (const auto& path : results) {
        bool exists = std::filesystem::exists(path);
        std::string status = exists ? "Present" : "Deleted";
        std::string sign = exists ? (IsFileSigned(std::wstring(path.begin(), path.end())) ? "Signed" : "Unsigned") : "-";

        // Unsigned: gelb/orange anzeigen
        if (sign == "Unsigned") {
            SetConsoleTextAttribute(hConsole, FOREGROUND_RED | FOREGROUND_GREEN | FOREGROUND_INTENSITY); // gelb/orange
        }

        std::cout << std::left << std::setw(static_cast<int>(colStart)) << path;

        if (!exists) {
            SetConsoleTextAttribute(hConsole, FOREGROUND_RED | FOREGROUND_INTENSITY);
            std::cout << std::left << std::setw(7) << "Deleted";
            SetConsoleTextAttribute(hConsole, FOREGROUND_RED | FOREGROUND_GREEN | FOREGROUND_BLUE);
        } else {
            std::cout << std::left << std::setw(7) << "Present";
        }

        std::cout << " | " << std::left << std::setw(9) << sign << "\n";

        // Nach jeder Zeile Farbe zurücksetzen
        SetConsoleTextAttribute(hConsole, FOREGROUND_RED | FOREGROUND_GREEN | FOREGROUND_BLUE);
    }

    std::cout << "\n------------------------------------------------------------------------\n\n";
}

int main() {
    SetConsoleTitleA("Explorer Memory Scanner");

    std::vector<std::string> pcaResults, explorerResults;

    DWORD explorerPID = findProcessId("explorer.exe");
    if (explorerPID) {
        scanProcess(explorerPID, pcaResults, explorerResults);
        std::sort(pcaResults.begin(), pcaResults.end());
        std::sort(explorerResults.begin(), explorerResults.end());
        printResults("PCAClient", pcaResults);
        printResults("Explorer", explorerResults);
    } else {
        std::cout << "\nExplorer.exe nicht gefunden.\n\n";
    }

    std::cout << "Press any key to exit...";
    std::cin.get();
    return 0;
}
