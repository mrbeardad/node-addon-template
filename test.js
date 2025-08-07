const addon = require("bindings")("my_addon");

process.on("uncaughtException", function (err) {
  console.log(err);
});

setInterval(() => {
  /* hang */
}, 1000);

addon.test();
