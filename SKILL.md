---
name: node-addon-template
description: Initialize a standalone C++ Node.js native addon workspace with cmake-js, Ninja, node-addon-api, Vitest, and an MSVC-aware PowerShell build wrapper.
---

# CMake.js Node Addon Init

Initialize a **standalone** C++ Node.js native addon workspace powered by **cmake-js**, **Ninja**, **node-addon-api** (Node-API), **Vitest**, and a Windows **PowerShell wrapper** that loads an exact Visual Studio C++ toolchain before invoking `cmake-js`.

The addon is always its own package/workspace root. The target directory must contain its own `package.json` after initialization, even when created inside a larger repository.

## When to Use

Use this skill when the user:

- Says "create a new native addon"
- Asks to "initialize a C++ node addon with cmake-js"
- Wants a standalone native addon package/workspace
- Needs a CMake-based replacement for node-gyp
- Wants Node-API tests wired through Vitest
- Wants reproducible Windows builds through a pinned MSVC toolset and Windows SDK

## Step 1 — Resolve Required Inputs

The user may explicitly invoke this skill and may provide some or all required values in the prompt. First parse the prompt for provided values. Then discover recommended settings. Ask the user only for required values that are missing or unclear.

Required values:

1. **`addonName`** — Addon name used as the `.node` binary name and CMake project name.
2. **Target directory** — The standalone addon root. The target directory is the addon's package root and must own its `package.json`; never mutate a parent workspace package.
3. **Node/cmake-js target settings**:
   - `napiVersion`
   - `cmake-js.runtime`
   - `cmake-js.runtimeVersion`
   - `cmake-js.arch`
4. **Windows toolchain settings**:
   - `windowsSdkVersion`
   - `msvcVersion`

Recommended settings:

- `addonName`: use the prompt value if provided; otherwise recommend the target directory's `package.json` `name` without `@scope/`, or the target directory basename.
- Target directory: recommend the workspace root unless the prompt clearly requests a subdirectory.
- `napiVersion`: recommend `node -p "process.versions.napi"`.
- `cmake-js.runtime`: recommend `node`.
- `cmake-js.runtimeVersion`: recommend `node -p "process.versions.node"`.
- `cmake-js.arch`: recommend `node -p "process.arch"`.
- `windowsSdkVersion`: prefer `10.0.22621.0`; if unavailable during discovery, recommend the latest installed Windows SDK.
- `msvcVersion`: prefer `14.38`; if unavailable during discovery, recommend the latest installed MSVC toolset prefix.

If any required value is missing or ambiguous, ask the user in this step and show the recommended value. Do not proceed until all required values are resolved. Fallback is allowed only while choosing recommendations in this step; the generated `scripts/cmake-js-msvc.ps1` must be strict with the selected `windowsSdkVersion` and `msvcVersion`.

## Step 2 — Read and merge package.json

The target directory is a standalone addon package. It must have its own `package.json`.

Read files from the chosen target directory only:

- If `package.json` exists, note existing `dependencies`, `devDependencies`, `scripts`, `binary`, `main`, `types`, `packageManager`, and `cmake-js` before merging.
- If `CMakeLists.txt` exists, warn the user and ask for confirmation before overwriting it.

If `package.json` exists in the target directory: read it, preserve ALL existing keys, add/merge only what's missing.

If `package.json` does NOT exist in the target directory: create it with this structure:

```json
{
  "name": "<addonName>",
  "version": "1.0.0",
  "description": "Node.js native addon built with cmake-js + node-addon-api",
  "binary": {
    "napi_versions": [<napiVersion>]
  },
  "main": "index.js",
  "types": "index.d.ts",
  "scripts": {
    "clean": "pwsh -NoProfile -ExecutionPolicy Bypass -File scripts/cmake-js-msvc.ps1 clean",
    "configure": "pwsh -NoProfile -ExecutionPolicy Bypass -File scripts/cmake-js-msvc.ps1 configure -G Ninja --CDCMAKE_EXPORT_COMPILE_COMMANDS=ON",
    "build": "pwsh -NoProfile -ExecutionPolicy Bypass -File scripts/cmake-js-msvc.ps1 compile -G Ninja --CDCMAKE_EXPORT_COMPILE_COMMANDS=ON",
    "rebuild": "pwsh -NoProfile -ExecutionPolicy Bypass -File scripts/cmake-js-msvc.ps1 rebuild -G Ninja --CDCMAKE_EXPORT_COMPILE_COMMANDS=ON",
    "test": "vitest run --globals"
  },
  "dependencies": {
    "node-addon-api": "*"
  },
  "devDependencies": {
    "cmake-js": "*",
    "vitest": "*"
  },
  "cmake-js": {
    "runtime": "<runtime>",
    "runtimeVersion": "<runtimeVersion>",
    "arch": "<arch>"
  }
}
```

> **Note on versions:** The template uses `*` to let the package manager resolve the latest compatible version. After `pnpm install`, the lockfile pins exact versions — no further action needed. If you manually edit `package.json` later, use the resolved versions from the lockfile.

**Merging rules when package.json exists:**

- `"name"`: keep existing
- `"version"`: keep existing
- `"description"`: keep existing
- `"main"`: set to `"index.js"` if not already set
- `"types"`: set to `"index.d.ts"` if not already set
- `"binary"`: add with `napi_versions` if not present
- `"scripts"`: add ONLY scripts that don't already exist (never overwrite existing scripts). New build scripts must call `scripts/cmake-js-msvc.ps1`, not `cmake-js` directly.
- `"dependencies"`: add `"node-addon-api"` if missing; if it exists use the existing version range
- `"devDependencies"`: add `"cmake-js"` and `"vitest"` if missing; if they exist use the existing version ranges
- `"cmake-js"`: add if missing; if present, preserve existing keys and add only missing `runtime`, `runtimeVersion`, and `arch` settings
- `"packageManager"`: preserve existing

## Step 3 — Create scripts/cmake-js-msvc.ps1

Always create `scripts/cmake-js-msvc.ps1`. This is the single build wrapper used by `clean`, `configure`, `build`, and `rebuild` package scripts.

The script must:

- accept the `cmake-js` command as the first positional argument
- accept and forward all remaining command-line arguments to `cmake-js`
- resolve Visual Studio through `vswhere.exe`
- import `Microsoft.VisualStudio.DevShell.dll`
- call `Enter-VsDevShell` with `-Arch x64`, `-HostArch x64`, and exact `-DevCmdArguments "-vcvars_ver=<msvcVersion> -winsdk=<windowsSdkVersion>"`
- verify the selected MSVC `<msvcVersion>*` exists under `VC\Tools\MSVC`
- verify the selected Windows SDK `<windowsSdkVersion>` exists under `Windows Kits\10\Include`
- fail with a clear error if any required toolchain component is missing
- invoke the local `node_modules/.bin/cmake-js` binary directly, without hardcoding `pnpm`, `npm`, or `yarn`

```powershell
[CmdletBinding()]
param(
  [Parameter(Mandatory = $true, Position = 0)]
  [ValidateSet("configure", "compile", "build", "rebuild", "clean")]
  [string] $Command,

  [Parameter(Position = 1, ValueFromRemainingArguments = $true)]
  [string[]] $CmakeJsArgs = @(),

  [Parameter()]
  [string] $Arch = "x64",

  [Parameter()]
  [string] $HostArch = "x64",

  [Parameter()]
  [string] $WindowsSdkVersion = "<windowsSdkVersion>",

  [Parameter()]
  [string] $MsvcVersion = "<msvcVersion>"
)

$ErrorActionPreference = "Stop"
Set-StrictMode -Version Latest

function Resolve-VsWhere {
  $programFilesX86 = [Environment]::GetFolderPath("ProgramFilesX86")
  $candidate = Join-Path $programFilesX86 "Microsoft Visual Studio\Installer\vswhere.exe"

  if (Test-Path -LiteralPath $candidate -PathType Leaf) {
    return $candidate
  }

  $command = Get-Command "vswhere.exe" -ErrorAction SilentlyContinue
  if ($null -ne $command) {
    return $command.Source
  }

  throw "Unable to find vswhere.exe. Install Visual Studio Installer or add vswhere.exe to PATH."
}

function Resolve-VisualStudioInstallation {
  $vswhere = Resolve-VsWhere
  $installations = & $vswhere -latest -products * -requires Microsoft.VisualStudio.Component.VC.Tools.x86.x64 -format json | ConvertFrom-Json

  if ($LASTEXITCODE -ne 0 -or $null -eq $installations) {
    throw "Unable to find a Visual Studio installation with MSVC C++ tools."
  }

  return $installations | Select-Object -First 1
}

function Import-VisualStudioDevShell {
  param(
    [Parameter(Mandatory = $true)]
    [string] $VsInstallPath
  )

  $modulePath = Join-Path $VsInstallPath "Common7\Tools\Microsoft.VisualStudio.DevShell.dll"
  $legacyModulePath = Join-Path $VsInstallPath "Common7\Tools\vsdevshell\Microsoft.VisualStudio.DevShell.dll"

  if (-not (Test-Path -LiteralPath $modulePath -PathType Leaf)) {
    $modulePath = $legacyModulePath
  }

  if (-not (Test-Path -LiteralPath $modulePath -PathType Leaf)) {
    throw "Microsoft.VisualStudio.DevShell.dll was not found under $VsInstallPath. Repair the Visual Studio installation."
  }

  Import-Module $modulePath
}

function Assert-RequiredToolchain {
  param(
    [Parameter(Mandatory = $true)]
    [string] $VsInstallPath
  )

  $msvcRoot = Join-Path $VsInstallPath "VC\Tools\MSVC"
  if (-not (Test-Path -LiteralPath $msvcRoot -PathType Container)) {
    throw "Visual Studio MSVC tools directory was not found: $msvcRoot"
  }

  $msvcToolset = Get-ChildItem -LiteralPath $msvcRoot -Directory |
    Where-Object { $_.Name -eq $MsvcVersion -or $_.Name.StartsWith("$MsvcVersion.") } |
    Sort-Object -Property Name -Descending |
    Select-Object -First 1

  if ($null -eq $msvcToolset) {
    throw "Required MSVC toolset $MsvcVersion was not found under $msvcRoot. Install MSVC v143 $MsvcVersion build tools."
  }

  $sdkIncludePath = Join-Path ${env:ProgramFiles(x86)} "Windows Kits\10\Include\$WindowsSdkVersion"
  if (-not (Test-Path -LiteralPath $sdkIncludePath -PathType Container)) {
    throw "Required Windows SDK $WindowsSdkVersion was not found at $sdkIncludePath. Install this exact Windows SDK version."
  }

  return $msvcToolset.Name
}

if ([string]::IsNullOrWhiteSpace($Command)) {
  throw "Usage: scripts/cmake-js-msvc.ps1 <configure|compile|build|rebuild|clean> [cmake-js arguments...]"
}

$visualStudio = Resolve-VisualStudioInstallation
$vsInstallPath = $visualStudio.installationPath
$vsInstanceId = $visualStudio.instanceId
$launchVsDevShell = Join-Path $vsInstallPath "Common7\Tools\Launch-VsDevShell.ps1"

if (-not (Test-Path -LiteralPath $launchVsDevShell -PathType Leaf)) {
  throw "Launch-VsDevShell.ps1 was not found at $launchVsDevShell"
}

$resolvedMsvcVersion = Assert-RequiredToolchain -VsInstallPath $vsInstallPath

$devCmdArguments = "-vcvars_ver=$MsvcVersion -winsdk=$WindowsSdkVersion"
Import-VisualStudioDevShell -VsInstallPath $vsInstallPath
Enter-VsDevShell -VsInstanceId $vsInstanceId -Arch $Arch -HostArch $HostArch -SkipAutomaticLocation -DevCmdArguments $devCmdArguments

if ($LASTEXITCODE -ne 0) {
  throw "Enter-VsDevShell failed with exit code $LASTEXITCODE."
}

$env:VCToolsVersion = $resolvedMsvcVersion
$env:WindowsSDKVersion = "$WindowsSdkVersion\"

$cmakeJsBin = Join-Path $PSScriptRoot "..\node_modules\.bin\cmake-js.cmd"
if (-not (Test-Path -LiteralPath $cmakeJsBin -PathType Leaf)) {
    throw "cmake-js was not found at $cmakeJsBin. Install project dependencies before building."
}

& $cmakeJsBin $Command @CmakeJsArgs
exit $LASTEXITCODE
```

## Step 4 — Create CMakeLists.txt

Always create (or overwrite with warning). Use `<addonName>` for the project name:

```cmake
cmake_minimum_required(VERSION 3.15)
project(<addonName>)

# Node-API
add_compile_definitions(NAPI_VERSION=<napiVersion>)

# Sources
file(GLOB SOURCE_FILES "src/*.cpp")

# Build shared library → .node
add_library(${PROJECT_NAME} SHARED ${SOURCE_FILES} ${CMAKE_JS_SRC})
set_target_properties(${PROJECT_NAME} PROPERTIES PREFIX "" SUFFIX ".node")

# C++ standard
target_compile_features(${PROJECT_NAME} PRIVATE cxx_std_20)

# Enable C++ exceptions for Node-API
target_compile_definitions(${PROJECT_NAME} PRIVATE NODE_ADDON_API_CPP_EXCEPTIONS NODE_ADDON_API_CPP_EXCEPTIONS_ALL)

# cmake-js provided paths
target_include_directories(${PROJECT_NAME} PRIVATE ${CMAKE_JS_INC})
target_link_libraries(${PROJECT_NAME} PRIVATE ${CMAKE_JS_LIB})

if(MSVC)
    # delayimp.lib needed for /DELAYLOAD:NODE.EXE on Windows
    target_link_libraries(${PROJECT_NAME} PRIVATE delayimp)

    # node.lib for Windows
    if(CMAKE_JS_NODELIB_DEF AND CMAKE_JS_NODELIB_TARGET)
        execute_process(COMMAND ${CMAKE_AR} /def:${CMAKE_JS_NODELIB_DEF} /out:${CMAKE_JS_NODELIB_TARGET} ${CMAKE_STATIC_LINKER_FLAGS})
    endif()

    # Generate pdb file for Release build
    target_compile_options(${PROJECT_NAME} PRIVATE
        "$<$<CONFIG:Release>:/Zi>"
    )
    target_link_options(${PROJECT_NAME} PRIVATE
        "$<$<CONFIG:Release>:/DEBUG>"
        "$<$<CONFIG:Release>:/OPT:REF>"
        "$<$<CONFIG:Release>:/OPT:ICF>"
    )

    # Set UTF-8 encoding for MSVC compiler
    target_compile_options(${PROJECT_NAME} PRIVATE /utf-8)
endif()

# Windows specific definitions
if(WIN32)
    target_compile_definitions(${PROJECT_NAME} PRIVATE WIN32_LEAN_AND_MEAN NOMINMAX UNICODE _UNICODE)
endif()
```

## Step 5 — Create .clangd

```yaml
CompileFlags:
  CompilationDatabase: build
Completion:
  AllScopes: yes
Hover:
  ShowAKA: yes
Documentation:
  CommentFormat: Doxygen
```

## Step 6 — Create .clang-format

```yaml
BasedOnStyle: Microsoft
SeparateDefinitionBlocks: Always
BreakTemplateDeclarations: Yes
PointerAlignment: Left
```

## Step 7 — Create .gitignore

Always create or merge this `.gitignore` in the standalone addon root:

```gitignore
node_modules/
.cache/
build/*
!build/*.node
coverage/
.vitest/
*.log
```

## Step 8 — Create .vscode/launch.json

Always create — no need to warn. This enables C++ debugging of the addon while running the Vitest test file.

```json
{
  "version": "0.2.0",
  "compounds": [
    {
      "name": "Debug C++ & JS (Vitest)",
      "configurations": ["Launch Vitest with C++ debugger", "Attach JS debugger"],
      "stopAll": true
    }
  ],
  "configurations": [
    {
      "name": "Launch Vitest with C++ debugger",
      "type": "cppvsdbg",
      "request": "launch",
      "program": "node",
      "args": [
        "--inspect-wait=9229",
        "${workspaceFolder}/node_modules/vitest/vitest.mjs",
        "run",
        "--globals",
        "--pool=threads",
        "--no-file-parallelism",
        "--maxWorkers=1"
      ],
      "cwd": "${workspaceFolder}",
      "console": "integratedTerminal",
      "symbolSearchPath": "${workspaceFolder}/build"
    },
    {
      "name": "Attach JS debugger",
      "type": "node",
      "request": "attach",
      "port": 9229,
      "address": "localhost",
      "restart": false,
      "timeout": 30000,
      "skipFiles": ["<node_internals>/**"]
    }
  ]
}
```

> **Note:** Launch the compound configuration `Debug C++ & JS (Vitest)` to debug both layers. The C++ debugger launches Node/Vitest and the JS debugger attaches on port `9229`. `--inspect-wait=9229` waits for the JS debugger without stopping on the first Vitest internals line, and `"restart": false` prevents VS Code from leaving the JS attach session running after Vitest exits. Set C++ breakpoints in `src/*.cpp`. Build first so `build/<addonName>.pdb` exists; use `pnpm run build -- -B Debug` for an explicit Debug build, or the default Release build with PDB symbols from the CMake template.

## Step 9 — Create placeholder source files

### `src/addon.cpp`

```cpp
#include <napi.h>

Napi::Value Hello(const Napi::CallbackInfo& info)
{
    return Napi::String::New(info.Env(), "Hello, world!");
}

Napi::Object Init(Napi::Env env, Napi::Object exports)
{
    exports["hello"] = Napi::Function::New<Hello>(env);
    return exports;
}

NODE_API_MODULE(<addonName>, Init)
```

### `index.js`

```js
// cmake-js + Ninja outputs to build/<addonName>.node
module.exports = require("./build/<addonName>.node");
```

### `index.d.ts`

```ts
export function hello(): string;
```

### `__test__/addon.test.js`

```js
const addon = require("../");

test("hello returns the native addon greeting", () => {
  expect(addon.hello()).toBe("Hello, world!");
});
```

## Step 10 — Post-creation instructions

After creating all files, tell the user:

```
Run the following to install dependencies and build:

  pnpm install
  pnpm run build

Then test with:

  pnpm test

For debug builds (with PDB symbols for C++ debugging), pass the explicit cmake-js config through the package script:

  pnpm run build -- -B Debug

The package scripts call `scripts/cmake-js-msvc.ps1`, which loads the pinned Windows toolchain before invoking `cmake-js`:

  Arch=x64
  HostArch=x64
  WindowsSdkVersion=<windowsSdkVersion>
  MsvcVersion=<msvcVersion>

The wrapper intentionally fails if the exact SDK or MSVC toolset is not installed.

Resolved settings were:

  NAPI_VERSION=<napiVersion>
  cmake-js.runtime=<runtime>
  cmake-js.runtimeVersion=<runtimeVersion>
  cmake-js.arch=<arch>
  WindowsSdkVersion=<windowsSdkVersion>
  MsvcVersion=<msvcVersion>

If these are not right for your target runtime, update `package.json` and `CMakeLists.txt` before building.
```

## Template Variable Reference

| Variable              | Source                                                                                   | Example        |
| --------------------- | ---------------------------------------------------------------------------------------- | -------------- |
| `<addonName>`         | User input (default: basename of target dir or package name)                             | `my_addon`     |
| `<napiVersion>`       | Silently detected with `node -p "process.versions.napi"`                                 | `10`           |
| `<runtime>`           | Defaulted silently for `cmake-js.runtime`                                                | `node`         |
| `<runtimeVersion>`    | Silently detected with `node -p "process.versions.node"`                                 | `24.14.0`      |
| `<arch>`              | Silently detected with `node -p "process.arch"`                                          | `x64`          |
| `<windowsSdkVersion>` | Preferred `10.0.22621.0`; if unavailable during discovery, latest installed Windows SDK  | `10.0.22621.0` |
| `<msvcVersion>`       | Preferred `14.38`; if unavailable during discovery, latest installed MSVC toolset prefix | `14.38`        |

## Constraints

- The addon must be a standalone workspace/package with its own `package.json` in the target directory.
- **NEVER** overwrite `package.json`. Only merge missing keys.
- **NEVER** remove existing `"scripts"`, `"dependencies"`, or `"devDependencies"`.
- **NEVER** change existing `"name"` or `"version"` in package.json.
- If `CMakeLists.txt` already exists, warn the user and ask for confirmation before overwriting.
- All paths are relative to the standalone addon root.
- Use Vitest for JavaScript tests; do not generate a plain `node __test__/test.js` test script.
- Package `clean`, `configure`, `build`, and `rebuild` scripts must call `scripts/cmake-js-msvc.ps1`; do not call `cmake-js` directly from `package.json`.
- The `cmake-js` `--CDCMAKE_EXPORT_COMPILE_COMMANDS=ON` flag is MANDATORY in configure/build/rebuild scripts — it ensures `compile_commands.json` is generated for clangd.
- Windows discovery must prefer `Arch=x64`, `HostArch=x64`, `WindowsSdkVersion=10.0.22621.0`, and `MsvcVersion=14.38`; if the preferred SDK/toolset is unavailable during discovery, select the latest installed SDK/toolset.
- The generated wrapper must be strict with the selected Windows SDK and MSVC toolset. Runtime fallback inside `scripts/cmake-js-msvc.ps1` is not allowed.
