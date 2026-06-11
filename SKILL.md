---
name: node-addon-template
description: Initialize a standalone C++ Node.js native addon workspace with cmake-js, Ninja, node-addon-api, and Vitest.
---

# CMake.js Node Addon Init

Initialize a **standalone** C++ Node.js native addon workspace powered by **cmake-js**, **Ninja**, **node-addon-api** (Node-API), and **Vitest**.

The addon is always its own package/workspace root. The target directory must contain its own `package.json` after initialization, even when created inside a larger repository.

## When to Use

Use this skill when the user:

- Says "create a new native addon"
- Asks to "initialize a C++ node addon with cmake-js"
- Wants a standalone native addon package/workspace
- Needs a CMake-based replacement for node-gyp
- Wants Node-API tests wired through Vitest

## Discovery Phase (MUST DO FIRST)

1. **Choose the standalone addon root**. The target directory is the root of the addon package and must have its own `package.json`.
2. **Check if `package.json` exists in the target directory**. If it does, READ it and merge into it. Do not use or mutate a parent workspace `package.json` as the addon package.
3. **Check if `CMakeLists.txt` exists** in the target directory — if so, warn before overwriting.
4. **Note any existing** `"dependencies"`, `"scripts"`, `"devDependencies"`, `"binary"`, `"main"`, `"types"`, `"packageManager"`, and `"cmake-js"` — you will merge into them, not replace.
5. **Silently detect defaults** without prompting the user:

- `napiVersion`: run `node -p "process.versions.napi"`
- `cmake-js.runtime`: use `node`
- `cmake-js.runtimeVersion`: run `node -p "process.versions.node"`
- `cmake-js.arch`: run `node -p "process.arch"`

6. **Verify cmake is available.** Run `cmake --version`. If not found in PATH, search for it under Visual Studio install paths:
   - Windows: `C:\Program Files\Microsoft Visual Studio\*\Community\Common7\IDE\CommonExtensions\Microsoft\CMake\CMake\bin\cmake.exe`
   - macOS: `/Applications/CMake.app/Contents/bin/cmake` or `/usr/local/bin/cmake`
   - Linux: `/usr/bin/cmake` or `/usr/local/bin/cmake`
     If not found, tell the user to install CMake. Do NOT proceed without it.

## Step 1 — Ask the User

Interactive UIs or CLI prompts — ask the user for ONLY these values (use your platform's native prompt mechanism; do NOT hardcode specific tool names):

1. **`addonName`** — Addon name (used as the `.node` binary name and CMake project name)
   - Default: the `name` from the target directory's `package.json` (strip `@scope/` if present), or the target directory basename

2. **Target directory** — Initialize the standalone addon workspace in the current workspace root, or in a subdirectory?
   - Default: workspace root
   - If a subdirectory is chosen, create and update files inside that subdirectory only
   - The chosen target directory must contain the addon's own `package.json`

Do NOT ask for `napiVersion` or `cmake-js` runtime settings up front. Use the silently detected values. At the end, report those detected values and tell the user to update them if they are not right for the target runtime.

## Step 2 — Merge into package.json

The target directory is a standalone addon package. It must have its own `package.json`.

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
    "clean": "cmake-js clean",
    "configure": "cmake-js configure -G Ninja --CDCMAKE_EXPORT_COMPILE_COMMANDS=ON",
    "build": "cmake-js build -G Ninja --CDCMAKE_EXPORT_COMPILE_COMMANDS=ON",
    "rebuild": "cmake-js rebuild -G Ninja",
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
- `"scripts"`: add ONLY scripts that don't already exist (never overwrite existing scripts)
- `"dependencies"`: add `"node-addon-api"` if missing; if it exists use the existing version range
- `"devDependencies"`: add `"cmake-js"` and `"vitest"` if missing; if they exist use the existing version ranges
- `"cmake-js"`: add if missing; if present, preserve existing keys and add only missing `runtime`, `runtimeVersion`, and `arch` settings
- `"packageManager"`: preserve existing

## Step 3 — Create CMakeLists.txt

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

# cmake-js provided paths
target_include_directories(${PROJECT_NAME} PRIVATE ${CMAKE_JS_INC})
target_link_libraries(${PROJECT_NAME} PRIVATE ${CMAKE_JS_LIB})

# delayimp.lib needed for /DELAYLOAD:NODE.EXE on Windows
if(MSVC)
    target_link_libraries(${PROJECT_NAME} PRIVATE delayimp)
endif()

# node.lib for Windows
if(MSVC AND CMAKE_JS_NODELIB_DEF AND CMAKE_JS_NODELIB_TARGET)
    execute_process(COMMAND ${CMAKE_AR} /def:${CMAKE_JS_NODELIB_DEF} /out:${CMAKE_JS_NODELIB_TARGET} ${CMAKE_STATIC_LINKER_FLAGS})
endif()

# Enable C++ exceptions for Node-API
target_compile_definitions(${PROJECT_NAME} PRIVATE NODE_ADDON_API_CPP_EXCEPTIONS NODE_ADDON_API_CPP_EXCEPTIONS_ALL)

# Windows specific definitions
if(WIN32)
    target_compile_definitions(${PROJECT_NAME} PRIVATE WIN32_LEAN_AND_MEAN NOMINMAX UNICODE _UNICODE)
endif()

# C++ standard
target_compile_features(${PROJECT_NAME} PRIVATE cxx_std_20)
```

## Step 4 — Create .clangd

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

## Step 5 — Create .clang-format

```yaml
BasedOnStyle: Microsoft
SeparateDefinitionBlocks: Always
BreakTemplateDeclarations: Yes
PointerAlignment: Left
```

## Step 6 — Create .gitignore

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

## Step 7 — Create .vscode/launch.json

Always create — no need to warn. This enables C++ debugging of the addon while running the Vitest test file.

```json
{
  "version": "0.2.0",
  "configurations": [
    {
      "name": "Debug C++ addon (Vitest)",
      "type": "cppvsdbg",
      "request": "launch",
      "program": "node",
      "args": [
        "${workspaceFolder}\\node_modules\\vitest\\vitest.mjs",
        "run",
        "--globals",
        "${workspaceFolder}\\__test__\\addon.test.js"
      ],
      "cwd": "${workspaceFolder}"
    },
    {
      "name": "Debug C++ + JS (hybrid)",
      "type": "node",
      "request": "launch",
      "program": "${workspaceFolder}\\node_modules\\vitest\\vitest.mjs",
      "args": ["run", "--globals", "${workspaceFolder}\\__test__\\addon.test.js"],
      "cwd": "${workspaceFolder}",
      "console": "integratedTerminal",
      "serverReadyAction": {
        "pattern": "Debugger listening on ws://\\S+:9229",
        "action": "startDebugging",
        "name": "Attach C++ debugger"
      }
    },
    {
      "name": "Attach C++ debugger",
      "type": "cppvsdbg",
      "request": "attach",
      "processId": "${command:pickProcess}"
    }
  ]
}
```

> **Note:** Set breakpoints in `src/*.cpp`. Build with `pnpm run build -- --debug` first for debug symbols. The hybrid config launches the JS debugger first, then attaches the C++ debugger — useful when debugging both layers simultaneously.

## Step 8 — Create placeholder source files

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

## Step 9 — Post-creation instructions

After creating all files, tell the user:

```
Run the following to install dependencies and build:

  pnpm install
  pnpm run build

Then test with:

  pnpm test

For debug builds (with PDB symbols for C++ debugging), pass --debug:

  pnpm run build -- --debug

Detected defaults were:

  NAPI_VERSION=<napiVersion>
  cmake-js.runtime=<runtime>
  cmake-js.runtimeVersion=<runtimeVersion>
  cmake-js.arch=<arch>

If these are not right for your target runtime, update `package.json` and `CMakeLists.txt` before building.
```

## Template Variable Reference

| Variable           | Source                                                       | Example    |
| ------------------ | ------------------------------------------------------------ | ---------- |
| `<addonName>`      | User input (default: basename of target dir or package name) | `my_addon` |
| `<napiVersion>`    | Silently detected with `node -p "process.versions.napi"`     | `10`       |
| `<runtime>`        | Defaulted silently for `cmake-js.runtime`                    | `node`     |
| `<runtimeVersion>` | Silently detected with `node -p "process.versions.node"`     | `24.14.0`  |
| `<arch>`           | Silently detected with `node -p "process.arch"`              | `x64`      |

## Constraints

- The addon must be a standalone workspace/package with its own `package.json` in the target directory.
- **NEVER** overwrite `package.json`. Only merge missing keys.
- **NEVER** remove existing `"scripts"`, `"dependencies"`, or `"devDependencies"`.
- **NEVER** change existing `"name"` or `"version"` in package.json.
- If `CMakeLists.txt` already exists, warn the user and ask for confirmation before overwriting.
- All paths are relative to the standalone addon root.
- Use Vitest for JavaScript tests; do not generate a plain `node __test__/test.js` test script.
- The `cmake-js` `--CDCMAKE_EXPORT_COMPILE_COMMANDS=ON` flag is MANDATORY in configure/build scripts — it ensures `compile_commands.json` is generated for clangd.
