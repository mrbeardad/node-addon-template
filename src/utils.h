#pragma once

#ifdef _WIN32
#define WIN32_LEAN_AND_MEAN
#include <Windows.h>
#include <TlHelp32.h>
#undef min
#undef max
#endif  // _WIN32

#include <string>
#include <vector>
#include <array>
#include <variant>
#include <ranges>
#include <random>

using namespace std::literals::string_literals;
using namespace std::literals::string_view_literals;
using namespace std::literals::chrono_literals;

namespace util {

namespace detail {

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

}  // namespace detail

#define STR_CONCAT_IMPL(x, y) x##y
#define STR_CONCAT(x, y) STR_CONCAT_IMPL(x, y)
#define UNIQUE_VARIABLE_NAME(prefix) STR_CONCAT(prefix, __LINE__)
#define defer auto UNIQUE_VARIABLE_NAME(_scope_exit_) = util::detail::ScopeExitDummy{} + [&]()

class SpinLock {
  std::atomic_bool locked_ = false;

  static constexpr size_t MAX_WAIT_ITERS = 4096;
  static constexpr size_t MIN_BACKOFF_ITERS = 8;
  static constexpr size_t MAX_BACKOFF_ITERS = 1024;

 public:
  FORCEINLINE void lock() {
    size_t curMaxDelay = MIN_BACKOFF_ITERS;

    while (true) {
      // WaitUntilLockIsFree();

      if (locked_.exchange(true, std::memory_order_acquire))
        BackoffExp(curMaxDelay);
      else
        break;
    }
  }

  FORCEINLINE bool try_lock() noexcept { return !locked_.exchange(true, std::memory_order_acquire); }

  FORCEINLINE void unlock() { locked_.store(false, std::memory_order_release); }

 private:
  FORCEINLINE static void CpuRelax() {
#ifdef _MSC_VER
    _mm_pause();
#elif defined(__GUNC__) || defined(__clang__)
    asm("pause");
#endif
  }

  FORCEINLINE static void YieldSleep() {
    // Don't yield but sleep to ensure that the thread is not
    // immediately run again in case scheduler's run queue is empty
    using namespace std::chrono;
    std::this_thread::sleep_for(500us);
  }

  FORCEINLINE static inline void BackoffExp(size_t& curMaxIters) {
    thread_local std::minstd_rand gen(std::random_device{}());
    thread_local std::uniform_int_distribution<size_t> dist;

    const size_t spinIters = dist(gen, decltype(dist)::param_type{0, curMaxIters});
    curMaxIters = std::min(2 * curMaxIters, MAX_BACKOFF_ITERS);

    for (size_t i = 0; i < spinIters; i++)
      CpuRelax();
  }

  FORCEINLINE void WaitUntilLockIsFree() const {
    size_t numIters = 0;

    while (locked_.load(std::memory_order_relaxed)) {
      if (numIters < MAX_WAIT_ITERS) {
        numIters++;
        CpuRelax();
      } else {
        YieldSleep();
      }
    }
  }
};

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

std::string bin2hex(std::string_view data) {
  std::stringstream ss;
  ss << std::hex;

  for (int i(0); i < data.size(); ++i)
    ss << std::setw(2) << std::setfill('0') << (int)data[i];

  return ss.str();
}

template <typename T>
inline T read(std::istream& s) {
  T x{};
  s.read(reinterpret_cast<char*>(&x), sizeof(T));
  return x;
}

template <>
inline std::string read(std::istream& s) {
  std::string str;
  std::getline(s, str, '\0');
  return str;
}

template <>
inline std::wstring read(std::istream& s) {
  std::wstring str;
  for (wchar_t c; (c = read<wchar_t>(s)) != L'\0';) {
    str += c;
  }
  return str;
}

inline std::string read(std::istream& s, size_t n) {
  std::string str(n, '\0');
  s.read(str.data(), n);
  return str;
}

/*
 * ============================================================================
 * Windows Only Utils
 * ============================================================================
 */
#ifdef _WIN32

inline namespace win {

inline std::u16string& w2ustring(std::wstring& s) {
  return *reinterpret_cast<std::u16string*>(&s);
}

inline const std::u16string& w2ustring(const std::wstring& s) {
  return *reinterpret_cast<const std::u16string*>(&s);
}

inline std::wstring& u2wstring(std::u16string& s) {
  return *reinterpret_cast<std::wstring*>(&s);
}

inline const std::wstring& u2wstring(const std::u16string& s) {
  return *reinterpret_cast<const std::wstring*>(&s);
}

inline std::string utf(const std::wstring_view& wstr) {
  std::string strTo;
  if (wstr.empty())
    return strTo;

  int size = ::WideCharToMultiByte(CP_UTF8, 0, wstr.data(), wstr.size(), NULL, 0, NULL, NULL);
  strTo.resize(size);
  ::WideCharToMultiByte(CP_UTF8, 0, wstr.data(), wstr.size(), strTo.data(), size, NULL, NULL);
  return strTo;
}

inline std::wstring utf(const std::string_view& str) {
  std::wstring wstrTo;
  if (str.empty())
    return wstrTo;

  int size = ::MultiByteToWideChar(CP_UTF8, 0, str.data(), str.size(), NULL, 0);
  wstrTo.resize(size);
  ::MultiByteToWideChar(CP_UTF8, 0, str.data(), str.size(), wstrTo.data(), size);
  return wstrTo;
}

struct AutoHandle {
  HANDLE handle = NULL;

  AutoHandle() = default;

  AutoHandle(HANDLE h) : handle(h) {}

  AutoHandle(const AutoHandle&) = delete;
  AutoHandle& operator=(const AutoHandle&) = delete;

  AutoHandle(AutoHandle&& other) noexcept : handle(other.handle) { other.handle = NULL; }

  AutoHandle& operator=(AutoHandle&& other) noexcept {
    if (&*this != &other) {
      if (handle) {
        ::CloseHandle(handle);
      }
      handle = other.handle;
      other.handle = NULL;
    }
    return *this;
  }

  ~AutoHandle() { Close(); }

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

  ::RegCloseKey(hKey);

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

inline bool KillProcessByName(const std::vector<std::wstring>& names, bool wait = true) {
  std::vector<HANDLE> hProcesses;

  EnumAllProcesses([&names, &hProcesses](const PROCESSENTRY32W& entry) {
    if (entry.th32ProcessID != 0 && std::any_of(names.begin(), names.end(), [exe = entry.szExeFile](const auto& name) {
          return ::_wcsicmp(exe, name.c_str()) == 0;
        })) {
      auto hProcess = ::OpenProcess(PROCESS_TERMINATE | SYNCHRONIZE, FALSE, entry.th32ProcessID);
      if (hProcess) {
        ::TerminateProcess(hProcess, 0);
        hProcesses.push_back(hProcess);
      }
    }
    return true;
  });

  if (wait && !hProcesses.empty()) {
    auto res = ::WaitForMultipleObjects(hProcesses.size(), hProcesses.data(), TRUE, INFINITE);

    for (auto hProcess : hProcesses) {
      ::CloseHandle(hProcess);
    }

    if (res < WAIT_OBJECT_0 || res >= WAIT_OBJECT_0 + hProcesses.size()) {
      return false;
    }
  }

  return true;
}

}  // namespace win

#endif  // _WIN32

}  // namespace util
