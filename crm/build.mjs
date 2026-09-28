// Wraps src/app.html in a full HTML document for the Worker to serve.
// (src/app.html is kept as a bare fragment so it can also be published
// as a standalone preview.)
import { readFileSync, writeFileSync, mkdirSync } from "node:fs";

const app = readFileSync(new URL("./src/app.html", import.meta.url), "utf8");
const page = `<!doctype html>
<html lang="en">
<head>
<meta charset="utf-8">
<meta name="viewport" content="width=device-width, initial-scale=1, viewport-fit=cover">
<meta name="color-scheme" content="light dark">
</head>
<body>
${app}
</body>
</html>
`;
mkdirSync(new URL("./public/", import.meta.url), { recursive: true });
writeFileSync(new URL("./public/index.html", import.meta.url), page);
console.log("Built public/index.html (" + page.length.toLocaleString() + " bytes)");
