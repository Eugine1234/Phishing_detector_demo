# Phishing_detector_demo
How It Works (Basic Logic)
The "Phishing URL Protector" is built entirely with HTML, Tailwind CSS for styling, and vanilla JavaScript for its core logic. When a user enters a URL and clicks "Check URL," the JavaScript performs the following checks:

URL Parsing: It first attempts to parse the input string into a valid URL object to extract components like the hostname (domain), path, and query parameters.

Hardcoded Blacklist Check:

It maintains a very small, hardcoded list of known (example) phishing domains.

If the entered URL's domain matches any in this list, it flags it as suspicious.

Limitation: This list is static and extremely limited; real blacklists contain millions of constantly updated entries.

Basic Typosquatting Detection:

It compares the entered URL's domain against a small, hardcoded list of legitimate root domains (e.g., google.com, amazon.com).

It looks for simple character substitutions (e.g., o becoming 0, l becoming 1 or i) that are common in typosquatting attempts (e.g., go0gle.com instead of google.com).

Limitation: This is a very primitive check and won't catch sophisticated typosquatting or homoglyph attacks.

HTTPS Check:

It verifies if the URL uses https:// (Hypertext Transfer Protocol Secure).

While HTTPS doesn't guarantee a site is legitimate, its absence (using http://) for a site requesting sensitive information is a major red flag.

Indicator: Flags if HTTPS is not used.

Suspicious Keywords in Path/Query:

It scans the URL's path and query parameters for common keywords often found in phishing URLs (e.g., login, verify, security, update, account).

Indicator: Flags if such keywords are present.

Based on these checks, the tool provides a visual indication (green for potentially safe, red for potential phishing) and lists the specific indicators found.

Setup and Usage
This project is a single-page application and requires no backend server to run.

Clone the Repository:

git clone https://github.com/your-username/phishing-url-protector.git
cd phishing-url-protector

(Replace your-username with your actual GitHub username)

Open in VS Code:

code .

Run the Application:

Open the index.html file in your web browser.

Recommended: If you have the "Live Server" extension installed in VS Code, right-click on index.html in the Explorer and select "Open with Live Server." This provides a live preview and auto-reloads on changes.

Alternatively, simply navigate to the index.html file in your file system and open it with your preferred browser.

Test: Enter various URLs (e.g., https://example.com, http://bad-site.com, https://paypa1.com/login-verify) to see how the detector responds.
