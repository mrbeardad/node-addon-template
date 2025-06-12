#pragma once

#include <Windows.h>
#include <TlHelp32.h>

#include <string>
#include <vector>
#include <array>
#include <variant>
#include <ranges>

namespace utils {

using RegType =
    std::variant<nullptr_t, DWORD, unsigned long long, std::vector<BYTE>, std::vector<std::wstring>, std::wstring>;

inline RegType ReadRegValue(HKEY rootKey,
                            const std::wstring& subKey,
                            const std::wstring& valueName,
                            DWORD* type = nullptr) {
  RegType var;

  HKEY hKey;
  LSTATUS result = ::RegOpenKeyExW(rootKey, subKey.c_str(), NULL, KEY_READ, &hKey);
  if (result != ERROR_SUCCESS) {
    return var;
  }

  DWORD dwType;
  DWORD cbData;
  result = ::RegQueryValueExW(hKey, valueName.c_str(), NULL, &dwType, NULL, &cbData);
  if (result != ERROR_SUCCESS) {
    return var;
  }
  if (type) {
    *type = dwType;
  }

  LPBYTE data = NULL;
  switch (dwType) {
    case REG_DWORD:
      var.emplace<DWORD>(0);
      data = reinterpret_cast<LPBYTE>(&std::get<DWORD>(var));
      break;

    case REG_QWORD:
      var.emplace<unsigned long long>(0);
      data = reinterpret_cast<LPBYTE>(&std::get<unsigned long long>(var));
      break;

    case REG_BINARY:
      var.emplace<std::vector<BYTE>>(cbData);
      data = reinterpret_cast<LPBYTE>(std::get<std::vector<BYTE>>(var).data());
      break;

    case REG_LINK:
    case REG_SZ:
    case REG_EXPAND_SZ:
    case REG_MULTI_SZ:
      var.emplace<std::wstring>(cbData / sizeof(WCHAR) - 1, '\0');
      data = reinterpret_cast<LPBYTE>(std::get<std::wstring>(var).data());
      break;

    default:
      break;
  }

  result = ::RegQueryValueExW(hKey, valueName.c_str(), NULL, &dwType, data, &cbData);

  RegCloseKey(hKey);

  if (result != ERROR_SUCCESS) {
    var.emplace<nullptr_t>(nullptr);
  } else if (dwType == REG_MULTI_SZ) {
    std::wstring& multiSz = std::get<std::wstring>(var);
    std::vector<std::wstring> multi;
    for (auto word : std::ranges::views::split(multiSz, std::wstring(1, L'\0'))) {
      multi.emplace_back(std::wstring(word.begin(), word.end()));
    }
    multi.erase(--multi.end());
    var.emplace<std::vector<std::wstring>>(std::move(multi));
  }

  return var;
}

inline void EnumAllProcesses(std::function<bool(const PROCESSENTRY32W&)> callback) {
  HANDLE snapshot = ::CreateToolhelp32Snapshot(TH32CS_SNAPPROCESS, NULL);
  if (snapshot == INVALID_HANDLE_VALUE) {
    return;
  }
  PROCESSENTRY32W entry{sizeof(PROCESSENTRY32W)};
  if (::Process32FirstW(snapshot, &entry)) {
    do {
      if (!callback(entry)) {
        break;
      }
    } while (::Process32NextW(snapshot, &entry));
  }
  ::CloseHandle(snapshot);
}

inline bool IsProcessElevated(DWORD pid) {
  bool isElevated = false;

  HANDLE hProcess = ::OpenProcess(PROCESS_QUERY_LIMITED_INFORMATION, FALSE, pid);
  if (hProcess) {
    HANDLE hToken = nullptr;
    if (::OpenProcessToken(hProcess, TOKEN_QUERY, &hToken)) {
      TOKEN_ELEVATION elevation;
      DWORD dwSize;
      if (::GetTokenInformation(hToken, TokenElevation, &elevation, sizeof(elevation), &dwSize)) {
        isElevated = elevation.TokenIsElevated != 0;
      }
      ::CloseHandle(hToken);
    }
    ::CloseHandle(hProcess);
  }

  return isElevated;
}

inline bool CreateProcessAsDesktopUser(const std::wstring& path, const std::wstring& argument) {
  // Find explorer.exe of current session
  DWORD sid = -1;
  if (!::ProcessIdToSessionId(::GetCurrentProcessId(), &sid)) {
    return false;
  }

  DWORD pid = 0;
  EnumAllProcesses([sid, &pid](const PROCESSENTRY32W& entry) {
    if (entry.th32ProcessID > 0 && ::_wcsicmp(entry.szExeFile, L"explorer.exe") == 0) {
      DWORD procSid = -1;
      if (::ProcessIdToSessionId(entry.th32ProcessID, &procSid) && procSid == sid) {
        pid = entry.th32ProcessID;
        return false;
      }
    }
    return true;
  });

  if (pid == 0) {
    return false;
  }

  bool ret = false;
  HANDLE hProcess = ::OpenProcess(PROCESS_QUERY_LIMITED_INFORMATION, FALSE, pid);
  if (hProcess) {
    HANDLE hToken;
    if (::OpenProcessToken(hProcess, TOKEN_DUPLICATE, &hToken)) {
      HANDLE hNewToken;
      if (::DuplicateTokenEx(
              hToken,
              TOKEN_QUERY | TOKEN_ASSIGN_PRIMARY | TOKEN_DUPLICATE | TOKEN_ADJUST_DEFAULT | TOKEN_ADJUST_SESSIONID,
              NULL, SecurityImpersonation, TokenPrimary, &hNewToken)) {
        auto cmdline = L"\"" + path + L"\" " + argument;
        auto dir = std::filesystem::path(path).parent_path();
        PROCESS_INFORMATION pi{};
        STARTUPINFOW si{};
        if (::CreateProcessAsUserW(hNewToken, NULL, cmdline.data(), NULL, NULL, FALSE, NULL, NULL, dir.c_str(), &si,
                                   &pi)) {
          ret = true;
          ::CloseHandle(pi.hProcess);
          ::CloseHandle(pi.hThread);
        }
        ::CloseHandle(hNewToken);
      }
      ::CloseHandle(hToken);
    }
    ::CloseHandle(hProcess);
  }

  return ret;
}

}  // namespace utils