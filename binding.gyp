{
  "variables": {
    "cppstd": "20",
  },
  "target_defaults": {
    "dependencies": ["<!(node -p \"require('node-addon-api').targets\"):node_addon_api_except_all"],
    "cflags_cc": ["-std=c++<(cppstd)"],
    "conditions": [
      [
        "OS=='win'",
        {
          "defines": ["_UNICODE", "UNICODE"],
          "configurations": {
            "Release": {
              "defines": ["NDEBUG"]
            }
          },
          "msvs_settings": {
            "VCCLCompilerTool": {
              "AdditionalOptions": ["%(AdditionalOptions)", "/std:c++<(cppstd)"]
            }
          }
        }
      ]
    ]
  },
  "targets": [
    {
      "target_name": "my_addon",
      "sources": ["<!(node -e \"require('fs').readdirSync('src', {withFileTypes:true}).filter(e => (e.isFile() && e.name.endsWith('.cpp'))).forEach(e => (console.log(path.join(e.parentPath, e.name).replace('\\\\', '\\\\\\\\'))))\")"],
      "include_dirs": [],
      "libraries": [],
      "defines": [],
    }
  ]
}
