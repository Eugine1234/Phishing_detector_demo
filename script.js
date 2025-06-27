// DOM Elements
const urlInput = document.getElementById('url-input');
const checkButton = document.getElementById('check-button');
const resultsContainer = document.getElementById('results-container');
const resultTitle = document.getElementById('result-title');
const resultList = document.getElementById('result-list');

// --- Configuration (for demonstration purposes) ---
const KNOWN_PHISHING_DOMAINS = [
    'paypal-verify.com', 'login-apple.net', 'microsoft-support.co',
    'amazon-secure-login.info', 'bankofamerica-update.xyz', 'wellsfargo-security.biz'
];

const LEGITIMATE_ROOT_DOMAains = [ // Corrected typo here from LEGITIMATE_ROOT_DOMAINS
    'google.com', 'microsoft.com', 'apple.com', 'amazon.com', 'paypal.com',
    'facebook.com', 'twitter.com', 'linkedin.com', 'ebay.com', 'netflix.com',
    'bankofamerica.com', 'wellsfargo.com', 'chase.com'
];

// Common typosquatting character substitutions
const TYPO_SUBSTITUTIONS = {
    'o': ['0'], 'l': ['1', 'i'], 'e': ['3'], 'a': ['@'], 's': ['5', '$'], 'g': ['9'],
    'm': ['rn'], 'rn': ['m'], 'vv': ['w'], 'w': ['vv'], 'cl': ['d']
};

const SUSPICIOUS_KEYWORDS = [
    'verify', 'login', 'security', 'update', 'account', 'invoice', 'payment', 'alert', 'urgent', 'confirm'
];

// --- Helper Functions ---

/**
 * Extracts the hostname (domain) from a URL.
 * @param {string} urlString - The full URL string.
 * @returns {string|null} The hostname or null if invalid.
 */
function getHostname(urlString) {
    try {
        const url = new URL(urlString);
        return url.hostname;
    } catch (error) {
        return null;
    }
}

/**
 * Checks if a domain is in the hardcoded blacklist.
 * @param {string} hostname - The hostname to check.
 * @returns {boolean} True if blacklisted, false otherwise.
 */
function checkBlacklist(hostname) {
    // Remove 'www.' if present for consistent checking
    const cleanedHostname = hostname.startsWith('www.') ? hostname.substring(4) : hostname;
    return KNOWN_PHISHING_DOMAINS.includes(cleanedHostname);
}

/**
 * Performs a basic typosquatting check against legitimate domains.
 * This is a simplified check, not exhaustive.
 * @param {string} inputHostname - The hostname to check.
 * @returns {boolean} True if looks like typosquatting, false otherwise.
 */
function checkTyposquatting(inputHostname) {
    const inputParts = inputHostname.split('.');
    let inputDomain = '';
    if (inputParts.length >= 2) {
        inputDomain = inputParts[inputParts.length - 2]; // Get domain without TLD
    } else {
        inputDomain = inputHostname;
    }

    for (const legitDomain of LEGITIMATE_ROOT_DOMAains) { // Corrected typo here from LEGITIMATE_ROOT_DOMAINS
        const legitRoot = legitDomain.split('.')[0]; // e.g., 'google' from 'google.com'

        // 1. Exact match (shouldn't happen if it's already considered phishing)
        if (inputDomain === legitRoot) return false;

        // 2. Length difference check (simple heuristic)
        if (Math.abs(inputDomain.length - legitRoot.length) > 2) continue; // Too different in length

        // 3. Basic character substitution check
        let potentialMatch = true;
        if (inputDomain.length === legitRoot.length) {
            for (let i = 0; i < inputDomain.length; i++) {
                const charInput = inputDomain[i];
                const charLegit = legitRoot[i];

                if (charInput !== charLegit) {
                    if (!TYPO_SUBSTITUTIONS[charLegit] || !TYPO_SUBSTITUTIONS[charLegit].includes(charInput)) {
                        potentialMatch = false;
                        break;
                    }
                }
            }
            if (potentialMatch) return true; // Found a substitution that looks like typosquatting
        }
    }
    return false;
}

/**
 * Checks if the URL uses HTTPS.
 * @param {string} urlString - The full URL string.
 * @returns {boolean} True if HTTPS, false otherwise.
 */
function checkHttps(urlString) {
    return urlString.startsWith('https://');
}

/**
 * Checks for suspicious keywords in the URL path or query.
 * @param {string} urlString - The full URL string.
 * @returns {boolean} True if suspicious keywords found, false otherwise.
 */
function checkSuspiciousKeywords(urlString) {
    try {
        const url = new URL(urlString);
        const pathAndQuery = (url.pathname + url.search).toLowerCase();
        return SUSPICIOUS_KEYWORDS.some(keyword => pathAndQuery.includes(keyword));
    } catch (error) {
        return false; // Invalid URL
    }
}

/**
 * Main function to analyze the URL and display results.
 */
function analyzeUrl() {
    const urlString = urlInput.value.trim();
    resultList.innerHTML = ''; // Clear previous results
    resultsContainer.classList.remove('bg-green-100', 'bg-yellow-100', 'bg-red-100');
    resultsContainer.classList.remove('border-green-300', 'border-yellow-300', 'border-red-300');

    if (!urlString) {
        displayResults('Please enter a URL.', 'neutral');
        return;
    }

    const hostname = getHostname(urlString);
    if (!hostname) {
        displayResults('Invalid URL format.', 'neutral');
        return;
    }

    let warnings = [];
    let indicators = [];

    // 1. Blacklist Check
    if (checkBlacklist(hostname)) {
        warnings.push('Domain is on a known (demo) phishing blacklist.');
    }

    // 2. Typosquatting Check
    if (checkTyposquatting(hostname)) {
        warnings.push('Domain appears to be a typosquatting attempt of a legitimate site.');
    }

    // 3. HTTPS Check
    if (!checkHttps(urlString)) {
        warnings.push('URL does NOT use HTTPS. This is highly suspicious for sensitive sites.');
    } else {
        indicators.push('Uses HTTPS (good, but not a guarantee of safety).');
    }

    // 4. Suspicious Keywords in Path/Query
    if (checkSuspiciousKeywords(urlString)) {
        warnings.push('URL path/query contains suspicious keywords (e.g., "login", "verify").');
    }

    // Determine overall result
    if (warnings.length > 0) {
        displayResults('Potential Phishing Detected!', 'warning', warnings, indicators);
    } else if (indicators.length > 0) {
        displayResults('Looks Potentially Safe (Basic Check)', 'safe', indicators);
    } else {
        displayResults('No Obvious Phishing Indicators (Basic Check)', 'safe');
    }
}

/**
 * Displays the analysis results in the UI.
 * @param {string} title - The main title for the result.
 * @param {'safe'|'warning'|'neutral'} type - The type of result to determine styling.
 * @param {Array<string>} [warnings=[]] - List of warning messages.
 * @param {Array<string>} [indicators=[]] - List of positive indicators.
 */
function displayResults(title, type, warnings = [], indicators = []) {
    resultTitle.textContent = title;
    resultList.innerHTML = '';
    resultsContainer.classList.remove('hidden');

    if (type === 'safe') {
        resultsContainer.classList.add('bg-green-100', 'border-green-300');
        resultTitle.classList.remove('text-red-800', 'text-orange-800');
        resultTitle.classList.add('text-green-800');
    } else if (type === 'warning') {
        resultsContainer.classList.add('bg-red-100', 'border-red-300');
        resultTitle.classList.remove('text-green-800', 'text-orange-800');
        resultTitle.classList.add('text-red-800');
    } else { // neutral
        resultsContainer.classList.add('bg-gray-100', 'border-gray-300');
        resultTitle.classList.remove('text-red-800', 'text-green-800');
        resultTitle.classList.add('text-gray-800');
    }

    warnings.forEach(msg => {
        const listItem = document.createElement('li');
        listItem.className = 'text-red-700 font-semibold';
        listItem.innerHTML = `⚠️ ${msg}`;
        resultList.appendChild(listItem);
    });

    indicators.forEach(msg => {
        const listItem = document.createElement('li');
        listItem.className = 'text-green-700';
        listItem.innerHTML = `✅ ${msg}`;
        resultList.appendChild(listItem);
    });

    if (warnings.length === 0 && indicators.length === 0 && type !== 'neutral') {
        const listItem = document.createElement('li');
        listItem.className = 'text-gray-600';
        listItem.textContent = 'No specific indicators detected by this basic tool.';
        resultList.appendChild(listItem);
    }
}

// --- Event Listener ---
checkButton.addEventListener('click', analyzeUrl);

// Allow pressing Enter in the input field
urlInput.addEventListener('keypress', (e) => {
    if (e.key === 'Enter') {
        analyzeUrl();
    }
});

// Initialize with a message to prompt user
document.addEventListener('DOMContentLoaded', () => {
    displayResults('Enter a URL to check...', 'neutral');
});
