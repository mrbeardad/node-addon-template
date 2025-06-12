const addon = require("./build/Debug/tool_helper.node");

process.on('uncaughtException', function (err) {
    console.log(err);
});

setInterval(() => { /* hang */ }, 1000)

addon.test()

