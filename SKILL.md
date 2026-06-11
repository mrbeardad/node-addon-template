---
name: cpp-node-addon-init
description: Initialize a C++ Node.js native addon project.
---

# CMake.js Node Addon Init

Initialize a C++ Node.js native addon project powered by **cmake-js**, **Ninja**, and **node-addon-api** (Node-API).

## When to Use

Use this skill when the user:

- Says "create a new native addon"
- Asks to "initialize a C++ node addon with cmake-js"
- Wants to add a native addon module to an existing npm project
- Needs a CMake-based replacement for node-gyp

## Discovery Phase (MUST DO FIRST)

1. **Check if `package.json` exists** in the target directory. If it does, READ it — you are adding to an existing project.
2. **Check if `CMakeLists.txt` exists** — if so, warn before overwriting.
3. **Note any existing** `"dependencies"`, `"scripts"`, `"devDependencies"`, `"binary"`, `"main"`, `"types"`, `"packageManager"` — you will merge into them, not replace.
4. **Verify cmake is available.** Run `cmake --version`. If not found in PATH, search for it under Visual Studio install paths:
   - Windows: `C:\Program Files\Microsoft Visual Studio\*\Community\Common7\IDE\CommonExtensions\Microsoft\CMake\CMake\bin\cmake.exe`
   - macOS: `/Applications/CMake.app/Contents/bin/cmake` or `/usr/local/bin/cmake`
   - Linux: `/usr/bin/cmake` or `/usr/local/bin/cmake`
     If not found, tell the user to install CMake. Do NOT proceed without it.

## Step 1 — Ask the User

Interactive UIs or CLI prompts — ask the user for these values (use your platform's native prompt mechanism; do NOT hardcode specific tool names):

1. **`napiVersion`** — Node-API version to target
   - Default: run `node -p "process.versions.napi"` and use the result
   - Suggested options: `9` (Node 20+), `8` (Node 18+), `7` (Node 16+)
   - Accept freeform input

2. **`addonName`** — Addon name (used as the .node binary name and CMake project name)
   - Default: the `name` from existing `package.json` (strip `@scope/` if present), or the current directory basename

3. **Target directory** — Initialize in current workspace root, or a subdirectory?
   - Default: workspace root. If a subdirectory, adjust ALL file paths below accordingly.

## Step 2 — Merge into package.json

If `package.json` exists: read it, preserve ALL existing keys, add/merge only what's missing.

If `package.json` does NOT exist: create it with this structure:

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
    "test": "node __test__/test.js"
  },
  "dependencies": {
    "node-addon-api": "*"
  },
  "devDependencies": {
    "cmake-js": "*"
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
- `"devDependencies"`: add `"cmake-js"` if missing; if it exists use the existing version range
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

# C++ standard
target_compile_features(${PROJECT_NAME} PRIVATE cxx_std_20)

# cmake-js provided paths
target_include_directories(${PROJECT_NAME} PRIVATE ${CMAKE_JS_INC})
target_link_libraries(${PROJECT_NAME} PRIVATE ${CMAKE_JS_LIB})

# delayimp.lib needed for /DELAYLOAD:NODE.EXE on Windows
if(MSVC)
    target_link_libraries(${PROJECT_NAME} PRIVATE delayimp)
endif()

# node.lib for Windows
if(MSVC AND CMAKE_JS_NODELIB_DEF AND CMAKE_JS_NODELIB_TARGET)
    execute_process(COMMAND ${CMAKE_AR} /def:${CMAKE_JS_NODELIB_DEF}
        /out:${CMAKE_JS_NODELIB_TARGET} ${CMAKE_STATIC_LINKER_FLAGS})
endif()

# Windows defines
if(WIN32)
    add_compile_definitions(WIN32_LEAN_AND_MEAN NOMINMAX UNICODE _UNICODE)
endif()
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

## Step 6 — Create .vscode/launch.json

Always create — no need to warn. This enables C++ debugging of the addon.

```json
{
  "version": "0.2.0",
  "configurations": [
    {
      "name": "Debug C++ addon (test.js)",
      "type": "cppvsdbg",
      "request": "launch",
      "program": "node",
      "args": ["${workspaceFolder}\\__test__\\test.js"],
      "cwd": "${workspaceFolder}"
    },
    {
      "name": "Debug C++ + JS (hybrid)",
      "type": "node",
      "request": "launch",
      "program": "${workspaceFolder}\\__test__\\test.js",
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

## Step 7 — Create placeholder source files

### `src/addon.cpp`

```cpp
#include <napi.h>

Napi::Value Hello(const Napi::CallbackInfo& info) {
    return Napi::String::New(info.Env(), "Hello, world!");
}

Napi::Object Init(Napi::Env env, Napi::Object exports) {
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

### `__test__/test.js`

```js
const addon = require("../");
console.log(addon.hello());
```

## Step 8 — Post-creation instructions

After creating all files, tell the user:

```
Run the following to install dependencies and build:

  pnpm install
  pnpm run build

Then test with:

  pnpm test

For debug builds (with PDB symbols for C++ debugging), pass --debug:

  pnpm run build -- --debug
```

## Template Variable Reference

| Variable        | Source                                                         | Example    |
| --------------- | -------------------------------------------------------------- | ---------- |
| `<addonName>`   | User input (default: basename of cwd or existing package name) | `my_addon` |
| `<napiVersion>` | User input (default: `node -p "process.versions.napi"`)        | `9`        |

## Constraints

- **NEVER** overwrite `package.json`. Only merge missing keys.
- **NEVER** remove existing `"scripts"`, `"dependencies"`, or `"devDependencies"`.
- **NEVER** change existing `"name"` or `"version"` in package.json.
- If `CMakeLists.txt` already exists, warn the user and ask for confirmation before overwriting.
- All paths are relative to the target directory (workspace root or user-specified subdirectory).
- The `cmake-js` `--CDCMAKE_EXPORT_COMPILE_COMMANDS=ON` flag is MANDATORY in configure/build scripts — it ensures `compile_commands.json` is generated for clangd.
