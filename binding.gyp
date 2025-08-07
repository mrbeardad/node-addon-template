{
  "variables": {
    "std": "c++20",
    "src_files": "<!(node -e \"require('fs').readdirSync('src', {withFileTypes:true}).filter(e => (e.isFile() && e.name.endsWith('.cpp'))).forEach(e => (console.log(path.join(e.parentPath, e.name).replace('\\\\', '\\\\\\\\'))))\")"
  },
  "target_defaults": {
    "sources": ["<@(src_files)"],
    "dependencies": ["<!(node -p \"require('node-addon-api').targets\"):node_addon_api_except_all"],
    "cflags_cc": ["-std=<(std)"],
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
              "AdditionalOptions": ["/std:<(std)"]
            }
          }
        }
      ]
    ]
  },
  "targets": [
    {
      "target_name": "my_addon",
      "include_dirs": [],
      "libraries": [],
      "defines": [],
    }
  ]
}
