#pragma once

#include <Windows.h>
#include <TlHelp32.h>

#include <string>
#include <vector>
#include <array>
#include <variant>
#include <ranges>

namespace util {

enum class ScopeExitDummy {};

template <typename T>
class ScopeExit {
 public:
  ScopeExit(T&& codeChunk_) : f_(std::forward<T>(codeChunk_)) {}

  ScopeExit(ScopeExit<T>&& other) : f_(std::move(other.f_)) {}

  ~ScopeExit() { f_(); }

 private:
  T f_;
};

template <typename T>
inline ScopeExit<T> operator+(ScopeExitDummy, T&& functor_) {
  return ScopeExit<T>{std::forward<T>(functor_)};
}

#define STR_CONCAT_IMPL(x, y) x##y
#define STR_CONCAT(x, y) STR_CONCAT_IMPL(x, y)
#ifdef __COUNTER__
  #define UNIQUE_VARIABLE(prefix) STR_CONCAT(prefix, __COUNTER__)
#else
  #define UNIQUE_VARIABLE(prefix) STR_CONCAT(prefix, __LINE__)
#endif
#define defer auto UNIQUE_VARIABLE(_scopeExit) = util::ScopeExitDummy{} + [&]

struct UniqueHandle {
  HANDLE handle = NULL;

  UniqueHandle() = default;

  UniqueHandle(HANDLE h) : handle(h) {}

  UniqueHandle(const UniqueHandle&) = delete;
  UniqueHandle& operator=(const UniqueHandle&) = delete;

  UniqueHandle(UniqueHandle&& other) noexcept : handle(other.handle) { other.handle = NULL; }

  UniqueHandle& operator=(UniqueHandle&& other) noexcept {
    if (&*this != &other) {
      if (handle) {
        ::CloseHandle(handle);
      }
      handle = other.handle;
      other.handle = NULL;
    }
    return *this;
  }

  ~UniqueHandle() { Close(); }

  HANDLE* operator&() { return &handle; }

  operator HANDLE() const { return handle; }

  void Close() {
    if (handle) {
      ::CloseHandle(handle);
      handle = NULL;
    }
  }
};

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
        STARTUPINFOW si{sizeof(si)};
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

int char2byte(char input) {
  if (input >= '0' && input <= '9')
    return input - '0';
  if (input >= 'A' && input <= 'F')
    return input - 'A' + 10;
  if (input >= 'a' && input <= 'f')
    return input - 'a' + 10;
  return -1;
}

std::string hex2bin(std::string_view hex) {
  if (hex.size() % 2 != 0) {
    return "";
  }

  std::string data(hex.size() / 2, '\0');
  for (size_t i = 0; i < hex.size(); i += 2) {
    uint8_t hi = char2byte(hex[i]);
    uint8_t lo = char2byte(hex[i + 1]);
    if (hi == -1 || lo == -1) {
      return "";
    }
    data[i / 2] = static_cast<char>((hi << 4) | lo);
  }
  return data;
}

std::string bin2hex(const uint8_t* data, int len) {
  std::stringstream ss;
  ss << std::hex;

  for (int i(0); i < len; ++i)
    ss << std::setw(2) << std::setfill('0') << (int)data[i];

  return ss.str();
}

std::string bin2hex(std::string data) {
  return bin2hex(reinterpret_cast<const uint8_t*>(data.data()), data.size());
}

}  // namespace util
