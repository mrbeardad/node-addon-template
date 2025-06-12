{
  "targets": [
    {
      "target_name": "addon",
      "sources": ["src/addon.cpp"],
      "dependencies": [
        "<!(node -p \"require('node-addon-api').targets\"):node_addon_api_except_all"
      ],
      "conditions": [
        [
          "OS=='win'",
          {
            "defines": ["_UNICODE", "UNICODE"],
            "configurations": {
              "Release": {
                "defines": ["NDEBUG"]
              }
            }
          }
        ]
      ]
    }
  ]
}
