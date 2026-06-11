const addon = require("../");

test("hello returns the native addon greeting", () => {
  expect(addon.hello()).toBe("Hello, world!");
});
