MiniTools

MiniTools is a small collection of browser utilities for everyday text, data, web and file tasks.

Included tools
- JSON Formatter
- Base64
- UUID Generator
- Hash Generator
- QR Generator
- Timestamp Converter
- Regex Tester
- URL Encoder
- Text Cleaner
- Word Counter
- Case Converter
- Markdown Preview
- Color Converter
- Number Base Converter
- List Tools
- Password Generator
- Image Compressor
- XML Formatter

Run locally
1. Download or clone the project.
2. Open index.html in a modern browser.

Deploy to Render
1. Put index.html, logo.png and README.txt in the root of your GitHub repository.
2. In Render, choose New > Static Site.
3. Connect the GitHub repository and the main branch.
4. Leave the build command empty.
5. Set the publish directory to .
6. Deploy the site.

The project does not require Node.js, a server, Docker, or a package manager.

Privacy
Most tools process the provided data directly in your browser. The QR generator uses the QR library loaded from a public CDN. No account is required.

For production use, serve the site over HTTPS. Some browser APIs, including Web Crypto hashing, require a secure context.
