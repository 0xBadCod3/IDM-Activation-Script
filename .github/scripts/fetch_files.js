const https = require('https');
const fs = require('fs');
const path = require('path');
const zlib = require('zlib');
const { pipeline } = require('stream/promises');
const { URL } = require('url');

// --- Configuration & Environment ---

const TOPIC_URL = process.env.RINRU_TOPIC || 'https://cs.rin.ru/forum/viewtopic.php?f=14&t=27045';
const POST_AUTHOR = (process.env.RINRU_AUTHOR || 'LuKeStorm').trim();
const SECTION_KEYWORD = (process.env.RINRU_SECTION || 'Fix').trim();
// Storage directories (.github/cache by default)
const defaultCacheDir = path.resolve(__dirname, '..', 'cache');
const OUTPUT_DIR = process.env.OUTPUT_DIR || defaultCacheDir;
const FORCE_FETCH = (process.env.FORCE_FETCH || '').toLowerCase() === 'true';

// Cache file configuration (.github/cache/version_cache.json by default)
const defaultCachePath = path.resolve(defaultCacheDir, 'version_cache.json');
const rootCachePath = path.resolve(__dirname, '..', '..', 'version_cache.json');
const oldGithubCachePath = path.resolve(__dirname, '..', 'version_cache.json');
const CACHE_FILE = process.env.CACHE_FILE || (
    fs.existsSync(defaultCachePath) ? defaultCachePath :
    fs.existsSync(rootCachePath) ? rootCachePath :
    fs.existsSync(oldGithubCachePath) ? oldGithubCachePath :
    defaultCachePath
);

const USERNAME = process.env.RINRU_USER || '';
const PASSWORD = process.env.RINRU_PASS || '';
const SAVED_COOKIE = process.env.RINRU_SESSION || '';
const COOKIE_OUTPUT_FILE = process.env.COOKIE_OUTPUT_FILE || '';

// --- GitHub Actions Secret Masking & Output ---

/**
 * Registers a secret with GitHub Actions runner log scrubber so it is masked as ***.
 */
function maskSecretInActions(secret) {
    if (process.env.GITHUB_ACTIONS === 'true' && secret && typeof secret === 'string' && secret.length >= 6) {
        process.stdout.write(`::add-mask::${secret}\n`);
    }
}

/**
 * Exports key-value pairs to $GITHUB_OUTPUT for workflow step chaining.
 */
function setGithubOutput(key, value) {
    if (process.env.GITHUB_OUTPUT) {
        try {
            fs.appendFileSync(process.env.GITHUB_OUTPUT, `${key}=${value}\n`);
        } catch {
            // Ignore if running outside GHA
        }
    }
}

// Mask known credentials immediately upon startup
if (PASSWORD) maskSecretInActions(PASSWORD);
if (USERNAME) maskSecretInActions(USERNAME);
if (SAVED_COOKIE) maskCookieValues(SAVED_COOKIE);

if (!fs.existsSync(OUTPUT_DIR)) {
    fs.mkdirSync(OUTPUT_DIR, { recursive: true });
}

const UA = 'Mozilla/5.0 (Windows NT 10.0; Win64; x64) AppleWebKit/537.36 (KHTML, like Gecko) Chrome/124.0.0.0 Safari/537.36';
const MAX_RETRIES = 3;
const FORUM_HOST = 'cs.rin.ru';

// Shared in-memory cookie jar
let activeCookies = SAVED_COOKIE || '';

// --- Version Cache Helpers ---

function readVersionCache() {
    if (!fs.existsSync(CACHE_FILE)) {
        return null;
    }
    try {
        const raw = fs.readFileSync(CACHE_FILE, 'utf8');
        return JSON.parse(raw);
    } catch (e) {
        console.warn(`  Warning: Could not parse version cache at ${CACHE_FILE}: ${e.message}`);
        return null;
    }
}

function writeVersionCache(versionInfo, downloadedFilename = null) {
    const dir = path.dirname(CACHE_FILE);
    if (!fs.existsSync(dir)) {
        fs.mkdirSync(dir, { recursive: true });
    }
    const cacheData = {
        latestVersion: versionInfo.normalized,
        rawVersion: versionInfo.raw,
        rinFetch: true,
        lastUpdated: new Date().toISOString(),
        downloadedFile: downloadedFilename || undefined,
    };
    fs.writeFileSync(CACHE_FILE, JSON.stringify(cacheData, null, 2) + '\n', 'utf8');
    console.log(`Updated repo version cache at ${CACHE_FILE}:`);
    console.log(JSON.stringify(cacheData, null, 2));
}

/**
 * Removes older version archives from the cache directory so only the latest version is retained.
 */
function cleanupOldCachedFiles(currentSafeFilename) {
    try {
        if (!fs.existsSync(OUTPUT_DIR)) return;
        const files = fs.readdirSync(OUTPUT_DIR);
        const archiveExtensions = ['.zip', '.rar', '.7z', '.tar', '.gz'];
        for (const file of files) {
            // Never delete version_cache.json or sha256 checksums
            if (file === 'version_cache.json' || file.endsWith('.sha256')) {
                continue;
            }
            const ext = path.extname(file).toLowerCase();
            if (archiveExtensions.includes(ext) && file !== currentSafeFilename) {
                const filePath = path.join(OUTPUT_DIR, file);
                console.log(`Removing old version archive from cache: ${file}`);
                try {
                    fs.unlinkSync(filePath);
                } catch (err) {
                    console.warn(`  Warning: Could not remove old file ${file}: ${err.message}`);
                }
            }
        }
    } catch (e) {
        console.warn(`  Warning: Could not cleanup old cached files: ${e.message}`);
    }
}

// --- Version Parsing & Futureproof Matching Engine ---

/**
 * Compares two parsed versions mathematically.
 * Returns > 0 if a > b, < 0 if a < b, 0 if equal.
 */
function compareVersions(a, b) {
    if (!a && !b) return 0;
    if (!a) return -1;
    if (!b) return 1;
    if (a.major !== b.major) return a.major - b.major;
    if (a.minor !== b.minor) return a.minor - b.minor;
    return (a.build || 0) - (b.build || 0);
}

/**
 * Checks if two versions are semantically identical (major, minor, and build match).
 */
function areVersionsEqual(a, b) {
    if (!a || !b) return false;
    return a.major === b.major && a.minor === b.minor && (a.build || 0) === (b.build || 0);
}

/**
 * Canonical display string for a version: e.g. "6.43 Build 10" or "6.44".
 */
function formatVersion(v) {
    if (!v) return '';
    return (v.build && v.build > 0) ? `${v.major}.${v.minor} Build ${v.build}` : `${v.major}.${v.minor}`;
}

/**
 * Extracts all valid IDM versions from any arbitrary text, HTML, or filename.
 * Robust against varied naming schemes (e.g. 6.43 Build 10, 6.43.10, 6.43b10, IDM_6.43_b10_fix, idman643build10.exe)
 * and safely ignores non-IDM versions (e.g. Windows 8.1, Chrome 31).
 */
function extractAllVersions(text) {
    if (!text || typeof text !== 'string') return [];
    const versions = [];
    const seen = new Set();

    function addVersion(majorStr, minorStr, buildStr, rawStr) {
        const major = parseInt(majorStr, 10);
        const minor = parseInt(minorStr, 10);
        const build = buildStr ? parseInt(buildStr, 10) : 0;

        // Valid IDM major version bounds (currently v6.x, allowing future v7-v30)
        if (isNaN(major) || major < 5 || major > 30) return;
        if (isNaN(minor) || minor < 0 || minor > 99) return;
        if (isNaN(build) || build < 0 || build > 999) return;

        const key = `${major}.${minor}.${build}`;
        if (!seen.has(key)) {
            seen.add(key);
            const normalized = formatVersion({ major, minor, build });
            versions.push({
                major,
                minor,
                build,
                majorMinor: `${major}.${minor}`,
                raw: rawStr ? rawStr.trim() : normalized,
                normalized,
            });
        }
    }

    // Pattern 1: Download executable names e.g. idman643build10.exe, idman643b10.exe, idman643.exe
    const exeRegex = /(?:^|[^0-9a-zA-Z])idman(\d{1,2})(\d{2})(?:(?:build|b)(\d{1,3}))?(?![0-9a-zA-Z])/gi;
    let m;
    while ((m = exeRegex.exec(text)) !== null) {
        addVersion(m[1], m[2], m[3], m[0]);
    }

    // Pattern 2: Explicit IDM prefix or version prefix e.g. 'IDM 6.43', 'IDM_6_43', 'version 6.43'
    const idmPrefixRegex = /(?:idm|idman|version|ver|v\.)[._\s-]*v?(\d{1,2})[._-](\d{1,2})(?:[._\s-]*(?:build|b|rev)[._\s-]*(\d{1,3})|[._-](\d{1,3}))?(?![0-9a-zA-Z])/gi;
    while ((m = idmPrefixRegex.exec(text)) !== null) {
        addVersion(m[1], m[2], m[3] || m[4], m[0]);
    }

    // Pattern 3: With explicit build/b keyword e.g. '6.43 Build 10', 'v6.43 b10', '6.43-Build-10', '6.43_b10'
    const buildRegex = /(?:^|[^0-9a-zA-Z])v?(\d{1,2})\.(\d{1,2})[.\s_-]*(?:build|b|rev)[.\s_-]*(\d{1,3})(?![0-9a-zA-Z])/gi;
    while ((m = buildRegex.exec(text)) !== null) {
        addVersion(m[1], m[2], m[3], m[0]);
    }

    // Pattern 4: Generic X.YY.ZZ or X.YY without OS/browser prefix
    // Matches '6.43.10' or 'v6.43.10' or '6.44' while safely ignoring 'Windows 8.1', 'Chrome 31'
    const genericRegex = /(?:^|[^0-9a-zA-Z])([a-zA-Z]+[\s_-]*)?v?(\d{1,2})\.(\d{1,2})(?:\.(\d{1,3}))?(?![0-9a-zA-Z])/gi;
    const osBlacklist = /^(?:windows|win|macos|mac|chrome|firefox|ie|edge|opera|android|ios|ubuntu|debian|linux)$/i;
    while ((m = genericRegex.exec(text)) !== null) {
        const prefixWord = (m[1] || '').trim().toLowerCase();
        if (prefixWord && osBlacklist.test(prefixWord)) {
            continue;
        }
        addVersion(m[2], m[3], m[4], m[0]);
    }

    return versions;
}

/**
 * Finds the highest IDM version contained anywhere within a text or HTML page.
 */
function findHighestVersion(text) {
    const all = extractAllVersions(text);
    if (all.length === 0) return null;
    all.sort((a, b) => compareVersions(b, a));
    return all[0];
}

/**
 * Parses any raw string into a structured IDM version object.
 */
function parseIdmVersion(rawVersion) {
    if (!rawVersion) return null;
    const clean = String(rawVersion).trim();
    const versions = extractAllVersions(clean);
    if (versions.length > 0) {
        versions.sort((a, b) => compareVersions(b, a));
        return versions[0];
    }
    return null;
}

/**
 * Scrapes the official Tonec IDM news page for the latest release version.
 * Utilizes multi-layer detection:
 * 1. Primary headline pattern ("What's new in version...")
 * 2. Universal page scanner taking the highest release version found
 */
async function fetchLatestOfficialIdmVersion() {
    console.log('Checking official IDM website for latest release (https://www.internetdownloadmanager.com/news.html)...');
    const res = await request('https://www.internetdownloadmanager.com/news.html');
    if (res.statusCode !== 200) {
        throw new Error(`Failed to fetch IDM news page, HTTP status: ${res.statusCode}`);
    }

    let versionObj = null;

    // Layer 1: Headline match (e.g. <H3>What's new in version 6.43 Build 10</H3>)
    const headingMatch = res.body.match(/<(?:h[1-6]|b|strong|div|p)[^>]*>\s*What['’]?s\s+new\s+in\s+version\s+([^<]+)<\/(?:h[1-6]|b|strong|div|p)>/i);
    if (headingMatch) {
        versionObj = parseIdmVersion(headingMatch[1]);
    }

    // Layer 2: Universal fallback / validation: scan all releases on news page
    const highestOnPage = findHighestVersion(res.body);

    if (!versionObj) {
        versionObj = highestOnPage;
    } else if (highestOnPage && compareVersions(highestOnPage, versionObj) > 0) {
        console.log(`  Note: found higher release (${highestOnPage.normalized}) on page than headline (${versionObj.normalized}).`);
        versionObj = highestOnPage;
    }

    if (!versionObj) {
        throw new Error('Could not parse latest IDM version from news.html');
    }

    console.log(`  Latest official IDM version detected: "${versionObj.normalized}"`);
    return versionObj;
}

/**
 * Checks whether a post HTML or text snippet contains the specified target version.
 */
function postMatchesVersion(postHtml, targetVersion) {
    if (!targetVersion) return true;
    const versions = extractAllVersions(postHtml);
    return versions.some(v => areVersionsEqual(v, targetVersion));
}

// --- Security & Cookie Helpers ---

/**
 * Checks whether a target URL belongs to the allowed forum domain.
 * Prevents sending session cookies to third-party domains on redirects.
 */
function isAllowedHost(targetUrl) {
    try {
        const parsed = new URL(targetUrl);
        return parsed.hostname === FORUM_HOST || parsed.hostname.endsWith('.' + FORUM_HOST);
    } catch {
        return false;
    }
}

/**
 * Sanitizes a filename from Content-Disposition or URL to prevent path traversal attacks.
 */
function sanitizeFilename(rawName, defaultName = `file_${Date.now()}.zip`) {
    if (!rawName) return defaultName;
    let name = rawName;
    try {
        if (name.includes('%')) name = decodeURIComponent(name);
    } catch {
        // Keep raw name if decoding fails
    }
    // Extract base name to strip directory traversal sequences
    name = path.basename(name);
    // Remove control characters, quotes, path separators, wildcards, and null bytes
    name = name.replace(/[<>:"/\\|?*\x00-\x1f]/g, '_').trim();
    if (!name || name === '.' || name === '..') return defaultName;
    return name;
}

/**
 * Extracts and masks individual cookie values in GitHub Actions logs.
 */
function maskCookieValues(cookieString) {
    if (!cookieString || typeof cookieString !== 'string') return;
    for (const item of cookieString.split(';')) {
        const trimmed = item.trim();
        const eqIdx = trimmed.indexOf('=');
        if (eqIdx > 0) {
            const val = trimmed.substring(eqIdx + 1).trim();
            maskSecretInActions(val);
        }
    }
}

/**
 * Persists updated session cookies with restricted file permissions (mode 0o600).
 * Never outputs cookie contents to stdout or stderr.
 */
function writeCookieFile(cookies) {
    if (!COOKIE_OUTPUT_FILE || !cookies) return;
    try {
        const dir = path.dirname(COOKIE_OUTPUT_FILE);
        if (!fs.existsSync(dir)) {
            fs.mkdirSync(dir, { recursive: true });
        }
        fs.writeFileSync(COOKIE_OUTPUT_FILE, cookies, { encoding: 'utf8', mode: 0o600 });
    } catch (e) {
        console.warn(`  Warning: Could not write session cookie to file: ${e.message}`);
    }
}

/**
 * Merges existing cookies with incoming Set-Cookie headers.
 * Safely handles key=value parsing where value may contain '='.
 */
function mergeCookies(oldCookies, newCookies) {
    const map = new Map();
    if (oldCookies) {
        for (const item of oldCookies.split(';')) {
            const trimmed = item.trim();
            if (!trimmed) continue;
            const eqIdx = trimmed.indexOf('=');
            if (eqIdx > 0) {
                const k = trimmed.substring(0, eqIdx).trim();
                const v = trimmed.substring(eqIdx + 1).trim();
                map.set(k, v);
            }
        }
    }

    if (Array.isArray(newCookies)) {
        for (const item of newCookies) {
            const firstPart = item.split(';')[0].trim();
            const eqIdx = firstPart.indexOf('=');
            if (eqIdx > 0) {
                const k = firstPart.substring(0, eqIdx).trim();
                const v = firstPart.substring(eqIdx + 1).trim();
                if (v === 'deleted' || !v) {
                    map.delete(k);
                } else {
                    map.set(k, v);
                }
            }
        }
    }

    return Array.from(map.entries()).map(([k, v]) => `${k}=${v}`).join('; ');
}

/**
 * Updates the global activeCookies, masks new tokens in CI logs, and writes to cookie file.
 */
function updateCookies(newCookies) {
    if (!newCookies) return activeCookies;
    if (Array.isArray(newCookies)) {
        activeCookies = mergeCookies(activeCookies, newCookies);
    } else if (typeof newCookies === 'string') {
        activeCookies = mergeCookies(activeCookies, newCookies.split(';'));
    }
    maskCookieValues(activeCookies);
    writeCookieFile(activeCookies);
    return activeCookies;
}

// --- HTTP Request Engine ---

/**
 * Decompresses HTTP response bodies transparently (gzip, deflate, brotli).
 */
function decompressBody(res, rawBuffer) {
    const encoding = (res.headers['content-encoding'] || '').toLowerCase();
    try {
        if (encoding === 'gzip') return zlib.gunzipSync(rawBuffer);
        if (encoding === 'deflate') return zlib.inflateSync(rawBuffer);
        if (encoding === 'br') return zlib.brotliDecompressSync(rawBuffer);
    } catch {
        // Fallback to raw buffer if decompression fails
    }
    return rawBuffer;
}

/**
 * Performs an HTTPS request with retries, timeout protection, and decompression.
 */
function request(url, opts = {}, retries = MAX_RETRIES) {
    return new Promise((resolve, reject) => {
        const doRequest = (attempt) => {
            let settled = false;
            const done = (fn, val) => {
                if (!settled) {
                    settled = true;
                    fn(val);
                }
            };

            const parsed = new URL(url);
            const headers = {
                'User-Agent': UA,
                'Accept': 'text/html,application/xhtml+xml,application/xml;q=0.9,*/*;q=0.8',
                'Accept-Language': 'en-US,en;q=0.9',
                'Accept-Encoding': 'gzip, deflate, br',
                'Sec-Fetch-Dest': 'document',
                'Sec-Fetch-Mode': 'navigate',
                'Sec-Fetch-Site': 'same-origin',
                ...(opts.headers || {}),
            };

            // Only attach cookies if targeting the allowed forum domain
            if (!isAllowedHost(url)) {
                delete headers['Cookie'];
            }

            const options = {
                hostname: parsed.hostname,
                port: parsed.port || 443,
                path: parsed.pathname + parsed.search,
                method: opts.method || 'GET',
                headers,
            };

            const req = https.request(options, (res) => {
                const chunks = [];
                let totalBytes = 0;
                const MAX_BODY_BYTES = 10 * 1024 * 1024; // 10MB safety cap for text responses

                res.on('data', (c) => {
                    totalBytes += c.length;
                    if (totalBytes <= MAX_BODY_BYTES) {
                        chunks.push(c);
                    }
                });

                res.on('end', () => {
                    const rawBuffer = Buffer.concat(chunks);
                    const decompressed = decompressBody(res, rawBuffer);
                    done(resolve, {
                        statusCode: res.statusCode,
                        headers: res.headers,
                        body: decompressed.toString('utf8'),
                        setCookies: res.headers['set-cookie'] || [],
                    });
                });
            });

            req.on('error', (err) => {
                if (attempt < retries) {
                    console.log(`  Retry ${attempt + 1}/${retries}...`);
                    setTimeout(() => doRequest(attempt + 1), 1000 * Math.pow(2, attempt));
                } else {
                    done(reject, err);
                }
            });

            req.setTimeout(30000, () => {
                req.destroy();
                if (attempt < retries) {
                    console.log(`  Retry (timeout) ${attempt + 1}/${retries}...`);
                    setTimeout(() => doRequest(attempt + 1), 1000 * Math.pow(2, attempt));
                } else {
                    done(reject, new Error('Request timed out after 30s'));
                }
            });

            if (opts.body) req.write(opts.body);
            req.end();
        };

        doRequest(0);
    });
}

// --- Security Interstitial Check ---

function extractSecurityTokens(body) {
    if (!body) return { token: null, expiry: null };
    const tokenMatch = body.match(/document\.cookie\s*=\s*["']?securitytoken=([^;"'\s]+)/i);
    const expiryMatch = body.match(/document\.cookie\s*=\s*["']?securitytoken_expiration=([^;"'\s]+)/i);
    return {
        token: tokenMatch ? tokenMatch[1] : null,
        expiry: expiryMatch ? expiryMatch[1] : null,
    };
}

async function passSecurityCheck() {
    console.log('Passing security check...');
    const r1 = await request('https://cs.rin.ru/forum/');
    console.log(`  GET /forum/ -> ${r1.statusCode}`);
    updateCookies(r1.setCookies);

    const { token, expiry } = extractSecurityTokens(r1.body);
    if (!token) {
        console.log('  No security token interstitial detected.');
        return activeCookies;
    }

    const cookieParts = ['securitytoken=' + token];
    if (expiry) cookieParts.push('securitytoken_expiration=' + expiry);
    updateCookies(cookieParts);

    const r2 = await request('https://cs.rin.ru/securitycheck/forum/', {
        headers: { Cookie: activeCookies },
    });
    console.log(`  GET /securitycheck/forum/ -> ${r2.statusCode}`);
    updateCookies(r2.setCookies);

    if (r2.statusCode >= 300 && r2.statusCode < 400 && r2.headers.location) {
        const redirUrl = new URL(r2.headers.location, 'https://cs.rin.ru/securitycheck/forum/').href;
        const r3 = await request(redirUrl, { headers: { Cookie: activeCookies } });
        updateCookies(r3.setCookies);
        console.log(`  Got ${r3.setCookies.length} session cookies from redirect.`);
    }

    return activeCookies;
}

async function passSecurityCheckWithCookies(token, expiry) {
    const cookieParts = ['securitytoken=' + token];
    if (expiry) cookieParts.push('securitytoken_expiration=' + expiry);
    updateCookies(cookieParts);

    const r = await request('https://cs.rin.ru/securitycheck/forum/', {
        headers: { Cookie: activeCookies },
    });
    updateCookies(r.setCookies);

    if (r.statusCode >= 300 && r.statusCode < 400 && r.headers.location) {
        const redirUrl = new URL(r.headers.location, 'https://cs.rin.ru/securitycheck/forum/').href;
        const r2 = await request(redirUrl, { headers: { Cookie: activeCookies } });
        updateCookies(r2.setCookies);
    }

    return activeCookies;
}

// --- Login & Validation ---

async function validateCookie() {
    if (!activeCookies) return false;
    console.log('  Validating saved session cookie...');
    try {
        let r = await request('https://cs.rin.ru/forum/', { headers: { Cookie: activeCookies } });
        if (r.statusCode === 401) {
            const { token, expiry } = extractSecurityTokens(r.body);
            if (token) {
                await passSecurityCheckWithCookies(token, expiry);
                r = await request('https://cs.rin.ru/forum/', { headers: { Cookie: activeCookies } });
            }
        }
        return r.body.includes('ucp.php?mode=logout');
    } catch {
        return false;
    }
}

/**
 * Extracts all hidden input elements from an HTML form for robust CSRF and session parameter passing.
 */
function extractHiddenInputs(html) {
    const inputs = {};
    const regex = /<input\b[^>]*>/gi;
    let m;
    while ((m = regex.exec(html)) !== null) {
        const tag = m[0];
        const typeMatch = tag.match(/type\s*=\s*["']?([^"'\s>]+)["']?/i);
        const type = typeMatch ? typeMatch[1].toLowerCase() : 'text';
        if (type === 'hidden') {
            const nameMatch = tag.match(/name\s*=\s*["']?([^"'\s>]+)["']?/i);
            const valMatch = tag.match(/value\s*=\s*["']?([^"'>]*)["']?/i);
            if (nameMatch) {
                inputs[nameMatch[1]] = valMatch ? valMatch[1] : '';
            }
        }
    }
    return inputs;
}

async function login() {
    console.log('Fetching login page...');
    const r1 = await request('https://cs.rin.ru/forum/ucp.php?mode=login', {
        headers: { Cookie: activeCookies },
    });
    updateCookies(r1.setCookies);

    // Extract all hidden inputs (sid, form_token, creation_time, redirect, etc.)
    const hiddenInputs = extractHiddenInputs(r1.body);

    console.log('Submitting login credentials...');
    const formParams = new URLSearchParams({
        ...hiddenInputs,
        username: USERNAME,
        password: PASSWORD,
        login: 'Login',
    });
    const body = formParams.toString();

    const r2 = await request('https://cs.rin.ru/forum/ucp.php?mode=login', {
        method: 'POST',
        headers: {
            Cookie: activeCookies,
            'Content-Type': 'application/x-www-form-urlencoded',
            'Content-Length': Buffer.byteLength(body),
            'Referer': 'https://cs.rin.ru/forum/ucp.php?mode=login',
        },
        body,
    });

    updateCookies(r2.setCookies);

    if (r2.statusCode === 302 || r2.body.includes('logout') || r2.body.includes('ucp.php?mode=logout')) {
        console.log('Login successful.');
        return activeCookies;
    }

    const errMatch = r2.body.match(/class="error"[^>]*>([^<]+)/);
    if (errMatch) {
        console.error(`  Login rejected: ${errMatch[1].trim()}`);
    } else {
        console.error('  Login failed. Check RINRU_USER and RINRU_PASS credentials.');
    }
    process.exit(1);
}

// --- DOM Parsing & Forum Topic Navigation ---

function stripHtml(html) {
    if (!html) return '';
    return html
        .replace(/<br\s*\/?>/gi, '\n')
        .replace(/<[^>]+>/g, ' ')
        .replace(/&amp;/g, '&')
        .replace(/&lt;/g, '<')
        .replace(/&gt;/g, '>')
        .replace(/&quot;/g, '"')
        .replace(/&#039;/g, "'")
        .replace(/&nbsp;/g, ' ')
        .replace(/\s+/g, ' ')
        .trim();
}

/**
 * Splits HTML page into individual post objects based on universal phpBB post anchors.
 */
function parsePostsFromHtml(html) {
    const posts = [];
    const anchorRegex = /(?:<div[^>]*\bid=["']p(\d+)["']|<a[^>]*\b(?:name|id)=["']p(\d+)["'])/gi;
    const matches = [];
    let m;
    while ((m = anchorRegex.exec(html)) !== null) {
        matches.push({
            id: m[1] || m[2],
            index: m.index,
        });
    }

    if (matches.length > 0) {
        for (let i = 0; i < matches.length; i++) {
            const start = matches[i].index;
            const end = (i + 1 < matches.length) ? matches[i + 1].index : html.length;
            posts.push({ id: matches[i].id, html: html.substring(start, end) });
        }
    } else {
        // Fallback for non-standard templates: split by tablebg rows or class="post"
        const fallbackRegex = /<(?:tr\s+class=["']row|div\s+class=["']post\b|table\s+class=["']tablebg)/gi;
        const fbMatches = [];
        while ((m = fallbackRegex.exec(html)) !== null) {
            fbMatches.push(m.index);
        }
        for (let i = 0; i < fbMatches.length; i++) {
            const start = fbMatches[i];
            const end = (i + 1 < fbMatches.length) ? fbMatches[i + 1] : html.length;
            posts.push({ id: `post_${i}`, html: html.substring(start, end) });
        }
    }

    return posts;
}

/**
 * Extracts the author of a post block while ignoring quotes from other users.
 */
function getPostAuthor(postHtml) {
    // Strip quote containers and citations to avoid matching quoted usernames
    const cleanHtml = postHtml
        .replace(/<blockquote[\s\S]*?<\/blockquote>/gi, '')
        .replace(/<cite[\s\S]*?<\/cite>/gi, '')
        .replace(/<div\s+class=["'][^"']*quote[^"']*["'][\s\S]*?<\/div>/gi, '');

    const patterns = [
        /<b[^>]*class=["'][^"']*\bpostauthor\b[^"']*["'][^>]*>\s*([^<]+)\s*<\/b>/i,
        /<span[^>]*class=["'][^"']*\bpostauthor\b[^"']*["'][^>]*>\s*([^<]+)\s*<\/span>/i,
        /<a[^>]*class=["'][^"']*\bpostauthor\b[^"']*["'][^>]*>\s*([^<]+)\s*<\/a>/i,
        /<td[^>]*class=["'][^"']*\bpostauthor\b[^"']*["'][^>]*>[\s\S]*?<b[^>]*>\s*([^<]+)\s*<\/b>/i,
        /<dt[^>]*class=["'][^"']*\bauthor\b[^"']*["'][^>]*>[\s\S]*?<a[^>]*>\s*([^<]+)\s*<\/a>/i,
        /<span[^>]*class=["'][^"']*\busername[^"']*["'][^>]*>\s*([^<]+)\s*<\/span>/i,
        /<a[^>]*class=["'][^"']*\busername[^"']*["'][^>]*>\s*([^<]+)\s*<\/a>/i,
        /<a[^>]*href=["'][^"']*viewprofile[^"']*["'][^>]*>\s*([^<]+)\s*<\/a>/i,
    ];

    for (const pat of patterns) {
        const match = cleanHtml.match(pat);
        if (match && match[1]) {
            return stripHtml(match[1]);
        }
    }
    return null;
}

/**
 * Extracts all download links from a post HTML snippet.
 */
function extractDownloadLinksFromPost(postHtml) {
    const links = [];
    const linkRegex = /<a\b[^>]*\bhref\s*=\s*["']?([^"'>]*download\/file\.php\?id=(\d+)[^"'>]*)["']?[^>]*>([\s\S]*?)<\/a>/gi;
    let m;
    while ((m = linkRegex.exec(postHtml)) !== null) {
        const fullHref = m[1];
        const id = m[2];
        const anchorText = stripHtml(m[3]);
        // Construct canonical absolute download URL
        const queryParams = fullHref.includes('&') ? fullHref.substring(fullHref.indexOf('&')) : '';
        const url = `https://cs.rin.ru/forum/download/file.php?id=${id}${queryParams}`;
        links.push({
            id,
            url,
            anchorText,
            raw: m[0],
            index: m.index,
        });
    }
    return links;
}

/**
 * Finds the most relevant download link matching the target section keyword (e.g. 'Fix') and target version.
 * Ensures that if targetVersion is provided, files belonging to older or different versions are strictly rejected.
 */
function findBestDownloadLink(postHtml, sectionKeyword, targetVersion = null) {
    const allLinks = extractDownloadLinksFromPost(postHtml);
    if (allLinks.length === 0) return null;

    const kwLower = sectionKeyword.toLowerCase();

    // Map each link with its extracted version metadata
    const linksWithMeta = allLinks.map(link => {
        const anchorVersions = extractAllVersions(link.anchorText + ' ' + link.url);
        const matchesTarget = targetVersion ? anchorVersions.some(v => areVersionsEqual(v, targetVersion)) : true;
        const hasOtherVersion = targetVersion ? (anchorVersions.length > 0 && !matchesTarget) : false;
        const hasKeyword = link.anchorText.toLowerCase().includes(kwLower);
        return {
            ...link,
            anchorVersions,
            matchesTarget,
            hasOtherVersion,
            hasKeyword,
        };
    });

    // Strategy 1: Link whose filename/anchor text matches BOTH section keyword (e.g. Fix) AND targetVersion
    if (targetVersion) {
        const exactMatch = linksWithMeta.find(l => l.matchesTarget && l.hasKeyword);
        if (exactMatch) {
            console.log(`    Matched link matching section and version: "${exactMatch.anchorText}"`);
            return exactMatch;
        }

        // Strategy 2: Link whose filename/anchor text matches targetVersion
        const versionMatch = linksWithMeta.find(l => l.matchesTarget);
        if (versionMatch) {
            console.log(`    Matched link matching target version in anchor text: "${versionMatch.anchorText}"`);
            return versionMatch;
        }
    }

    // Strategy 3: Link whose anchor text contains section keyword, provided it doesn't belong to a different version
    const kwMatch = linksWithMeta.find(l => l.hasKeyword && !l.hasOtherVersion);
    if (kwMatch) {
        console.log(`    Matched link by filename/anchor text: "${kwMatch.anchorText}"`);
        return kwMatch;
    }

    // Strategy 4: Section heading match - find heading containing keyword, then search for link in that section
    const headingRegex = /<(?:b|strong|span|h[1-6])\b[^>]*>([\s\S]*?)<\/(?:b|strong|span|h[1-6])>/gi;
    let h;
    while ((h = headingRegex.exec(postHtml)) !== null) {
        const headingText = stripHtml(h[1]).toLowerCase();
        if (headingText.includes(kwLower)) {
            const headingPos = h.index;
            const subHtml = postHtml.substring(headingPos, headingPos + 3000);
            const subLinks = extractDownloadLinksFromPost(subHtml);
            for (const sl of subLinks) {
                const slMeta = linksWithMeta.find(l => l.id === sl.id);
                if (slMeta && !slMeta.hasOtherVersion) {
                    console.log(`    Matched link in section heading "${stripHtml(h[1])}" -> file ID ${sl.id}`);
                    return sl;
                }
            }
        }
    }

    // Strategy 5: Text proximity fallback to sectionKeyword
    const text = stripHtml(postHtml).toLowerCase();
    const kwIdx = text.indexOf(kwLower);
    if (kwIdx !== -1) {
        let bestDist = Infinity;
        let bestProximityLink = null;
        for (const l of linksWithMeta) {
            if (l.hasOtherVersion) continue;
            const textBefore = stripHtml(postHtml.substring(0, l.index)).toLowerCase();
            const dist = Math.abs(textBefore.length - kwIdx);
            if (dist < bestDist) {
                bestDist = dist;
                bestProximityLink = l;
            }
        }
        if (bestProximityLink) {
            console.log(`    Matched link by proximity to "${sectionKeyword}" -> file ID ${bestProximityLink.id}`);
            return bestProximityLink;
        }
    }

    // Fallback: If targetVersion is specified, DO NOT pick a link that explicitly has another version
    const viableLinks = linksWithMeta.filter(l => !l.hasOtherVersion);
    if (viableLinks.length > 0) {
        return viableLinks[0];
    }

    // If all links explicitly belong to different versions, return null
    return null;
}

/**
 * Extracts pagination parameters (posts per page and highest start offset) from the HTML.
 */
function parsePaginationInfo(html) {
    let perPage = 15;
    let maxStart = 0;
    const allStarts = [];

    const startRegex = /[?&]start=(\d+)/gi;
    let m;
    while ((m = startRegex.exec(html)) !== null) {
        const val = parseInt(m[1], 10);
        if (!isNaN(val)) {
            allStarts.push(val);
            if (val > maxStart) maxStart = val;
        }
    }

    const sortedStarts = [...new Set(allStarts)].sort((a, b) => a - b);
    if (sortedStarts.length >= 2) {
        const diff = sortedStarts[1] - sortedStarts[0];
        if (diff > 0 && diff <= 100) perPage = diff;
    } else {
        const pageMatch = html.match(/Page\s*(?:<strong>|<b>)?\s*\d+\s*(?:<\/strong>|<\/b>)?\s*of\s*(?:<strong>|<b>)?\s*(\d+)/i);
        if (pageMatch) {
            const totalPages = parseInt(pageMatch[1], 10);
            if (totalPages > 1 && maxStart === 0) {
                maxStart = (totalPages - 1) * perPage;
            }
        }
    }

    return { perPage, maxStart };
}

/**
 * Searches topic pages to locate the author's post containing the target section and download link.
 * If targetVersion is provided, ensures the post matches the target version.
 */
async function findDownloadLink(targetVersion = null) {
    console.log(`\nNavigating topic: ${TOPIC_URL}`);
    console.log(`Target Author: "${POST_AUTHOR}" | Section: "${SECTION_KEYWORD}"`);
    if (targetVersion) {
        console.log(`Target Version to Match: "${targetVersion.normalized}"`);
    }

    const parsed = new URL(TOPIC_URL);
    const f = parsed.searchParams.get('f') || '14';
    const t = parsed.searchParams.get('t') || '27045';
    const initialStart = parseInt(parsed.searchParams.get('start'), 10) || 0;

    let start = initialStart;
    let perPage = 15;
    let maxStart = initialStart;
    let pagesChecked = 0;
    const MAX_PAGES_TO_SCAN = 60;
    let foundAuthorPost = false;

    while (pagesChecked < MAX_PAGES_TO_SCAN) {
        const pageUrl = `https://cs.rin.ru/forum/viewtopic.php?f=${f}&t=${t}&start=${start}`;
        console.log(`\nScanning page (start=${start})...`);
        const r = await request(pageUrl, { headers: { Cookie: activeCookies } });
        updateCookies(r.setCookies);

        if (r.statusCode !== 200) {
            console.error(`Failed to load topic page (HTTP ${r.statusCode})`);
            break;
        }

        // Parse pagination on initial page load
        if (pagesChecked === 0) {
            const pagInfo = parsePaginationInfo(r.body);
            perPage = pagInfo.perPage;
            maxStart = Math.max(maxStart, pagInfo.maxStart);
            console.log(`  Pagination info: ${perPage} posts/page, maxStart=${maxStart}`);
        }

        const posts = parsePostsFromHtml(r.body);
        console.log(`  Parsed ${posts.length} posts on page.`);

        // Find all posts on this page authored by POST_AUTHOR
        const authorPosts = posts.filter(p => {
            const author = getPostAuthor(p.html);
            return author && author.toLowerCase() === POST_AUTHOR.toLowerCase();
        });

        if (authorPosts.length > 0) {
            foundAuthorPost = true;
            console.log(`  Found ${authorPosts.length} post(s) by "${POST_AUTHOR}" on this page.`);

            // Search through author's posts for the section & download link
            for (const post of authorPosts) {
                // If targetVersion is provided, verify whether this post matches targetVersion
                if (targetVersion && !postMatchesVersion(post.html, targetVersion)) {
                    console.log(`  Post by "${POST_AUTHOR}" does not match target version "${targetVersion.normalized}".`);
                    continue;
                }

                const bestLink = findBestDownloadLink(post.html, SECTION_KEYWORD, targetVersion);
                if (bestLink) {
                    console.log(`  Selected download link: ${bestLink.url}`);
                    return bestLink.url;
                }
            }
        }

        // If not found, advance to the next page
        pagesChecked++;
        if (start >= maxStart) {
            break;
        }
        start += perPage;
    }

    if (foundAuthorPost && targetVersion) {
        console.log(`\nAuthor "${POST_AUTHOR}" post(s) were found, but none match required version "${targetVersion.normalized}".`);
    } else {
        console.log(`\nCould not find download link by author "${POST_AUTHOR}" for section "${SECTION_KEYWORD}".`);
    }
    return null;
}

// --- File Downloader ---

function downloadFile(url, redirectCount = 0) {
    if (redirectCount > 10) {
        return Promise.reject(new Error('Too many redirects while downloading file.'));
    }

    return new Promise((resolve, reject) => {
        const parsed = new URL(url);
        const headers = {
            'User-Agent': UA,
            'Referer': 'https://cs.rin.ru/forum/',
            'Accept': '*/*',
        };

        // Only pass cookies to the forum domain to prevent credential leaks to third parties
        if (isAllowedHost(url) && activeCookies) {
            headers['Cookie'] = activeCookies;
        }

        const options = {
            hostname: parsed.hostname,
            port: parsed.port || 443,
            path: parsed.pathname + parsed.search,
            method: 'GET',
            headers,
        };

        const req = https.request(options, async (res) => {
            updateCookies(res.headers['set-cookie']);

            // Handle security check 401 interstitial on download endpoint
            if (res.statusCode === 401) {
                const chunks = [];
                res.on('data', (c) => chunks.push(c));
                res.on('end', async () => {
                    const body = Buffer.concat(chunks).toString('utf8');
                    const { token, expiry } = extractSecurityTokens(body);
                    if (token) {
                        try {
                            await passSecurityCheckWithCookies(token, expiry);
                            downloadFile(url, redirectCount + 1).then(resolve).catch(reject);
                        } catch (e) {
                            reject(e);
                        }
                    } else {
                        reject(new Error('HTTP 401 Unauthorized during download'));
                    }
                });
                return;
            }

            // Follow HTTP redirects safely
            if (res.statusCode >= 300 && res.statusCode < 400 && res.headers.location) {
                const redir = new URL(res.headers.location, url).href;
                console.log(`  Download redirect (${res.statusCode}) -> ${new URL(redir).hostname}`);
                downloadFile(redir, redirectCount + 1).then(resolve).catch(reject);
                return;
            }

            if (res.statusCode !== 200) {
                reject(new Error(`Download failed with HTTP status ${res.statusCode}`));
                res.resume();
                return;
            }

            // Extract and sanitize filename to prevent path traversal
            const cd = res.headers['content-disposition'] || '';
            const utf8Match = cd.match(/filename\*=UTF-8''([^;\s]+)/i);
            const stdMatch = cd.match(/filename=["']?([^"';\n]+)["']?/i);
            let rawFilename = `file_${Date.now()}.zip`;

            if (utf8Match && utf8Match[1]) {
                rawFilename = utf8Match[1];
            } else if (stdMatch && stdMatch[1]) {
                rawFilename = stdMatch[1];
            } else {
                const urlPath = parsed.pathname;
                const base = path.basename(urlPath);
                if (base && !base.endsWith('.php')) rawFilename = base;
            }

            const safeFilename = sanitizeFilename(rawFilename);
            const destinationPath = path.resolve(OUTPUT_DIR, safeFilename);

            // Verify the resolved path is inside the designated OUTPUT_DIR
            if (!destinationPath.startsWith(path.resolve(OUTPUT_DIR) + path.sep)) {
                reject(new Error('Security violation: Attempted path traversal in filename.'));
                res.resume();
                return;
            }

            const total = parseInt(res.headers['content-length'], 10) || 0;
            let downloaded = 0;

            res.on('data', (chunk) => {
                downloaded += chunk.length;
                if (total) {
                    process.stdout.write(`\r  Progress: ${((downloaded / total) * 100).toFixed(1)}% (${downloaded}/${total} bytes)`);
                } else {
                    process.stdout.write(`\r  Progress: ${downloaded} bytes downloaded`);
                }
            });

            try {
                const fileWriteStream = fs.createWriteStream(destinationPath);
                await pipeline(res, fileWriteStream);
                console.log(`\nDownload completed. Saved to: ${destinationPath}`);
                resolve(destinationPath);
            } catch (err) {
                fs.unlink(destinationPath, () => {});
                reject(err);
            }
        });

        req.on('error', reject);
        req.setTimeout(120000, () => {
            req.destroy();
            reject(new Error('Download connection timed out after 120s'));
        });
        req.end();
    });
}

// --- Main Execution Flow ---

(async () => {
    // Step 1: Check official IDM website for the latest release
    const officialVersion = await fetchLatestOfficialIdmVersion();
    const cache = readVersionCache();
    const cachedVersion = cache ? parseIdmVersion(cache.latestVersion || cache.rawVersion) : null;

    // Step 2: Compare against local repo cache
    let needsFetch = false;
    if (FORCE_FETCH) {
        console.log('FORCE_FETCH is enabled. Forcing RIN forum check regardless of cache.');
        needsFetch = true;
    } else if (!cache || !cachedVersion) {
        console.log(`No valid existing version cache found at ${CACHE_FILE}. Proceeding to check RIN forum.`);
        needsFetch = true;
    } else if (compareVersions(officialVersion, cachedVersion) > 0) {
        console.log(`New official IDM version detected! Official: "${officialVersion.normalized}", Cached: "${cachedVersion.normalized}".`);
        needsFetch = true;
    } else if (cache.rinFetch !== true) {
        console.log(`Official version "${officialVersion.normalized}" matches cache, but rinFetch is not true. Proceeding to check RIN forum.`);
        needsFetch = true;
    } else {
        console.log(`\nOfficial version "${officialVersion.normalized}" is already cached and fetched (rinFetch: true).`);
        console.log('Skipping RIN access. All files are up to date.');
        setGithubOutput('downloaded', 'false');
        setGithubOutput('cache_updated', 'false');
        setGithubOutput('version', officialVersion.normalized);
        process.exit(0);
    }

    // Step 3: Access RIN Forum if new version is needed
    console.log('\nProceeding to check RIN forum for new version...');
    let sessionValid = false;
    if (activeCookies) {
        console.log('Validating saved session cookie...');
        sessionValid = await validateCookie();
        if (sessionValid) {
            console.log('Session cookie is valid. Proceeding without re-authenticating.');
        } else {
            console.log('Saved session is expired or invalid. Re-authenticating...');
        }
    }

    if (!sessionValid) {
        if (!USERNAME || !PASSWORD) {
            console.error('Error: Session cookie expired and no RINRU_USER / RINRU_PASS provided for re-login.');
            process.exit(1);
        }
        await passSecurityCheck();
        await login();
    }

    // Step 4: Locate target download URL matching official version
    const downloadUrl = await findDownloadLink(officialVersion);

    if (!downloadUrl) {
        console.log(`\nRIN forum post has not yet updated to version "${officialVersion.normalized}".`);
        console.log('Per requirements: doing nothing and leaving repo cache unchanged until RIN updates.');
        setGithubOutput('downloaded', 'false');
        setGithubOutput('cache_updated', 'false');
        setGithubOutput('version', officialVersion.normalized);
        process.exit(0);
    }

    // Step 5: Download and save the file safely
    console.log(`\nInitiating file download: ${downloadUrl}`);
    const destinationPath = await downloadFile(downloadUrl);
    const safeFilename = path.basename(destinationPath);

    // Remove older version archives from cache directory
    cleanupOldCachedFiles(safeFilename);

    // Step 6: Update repo cache JSON (rinFetch = true)
    writeVersionCache(officialVersion, safeFilename);

    // Step 7: Export outputs for GitHub Actions
    setGithubOutput('downloaded', 'true');
    setGithubOutput('cache_updated', 'true');
    setGithubOutput('version', officialVersion.normalized);
    setGithubOutput('downloaded_file', destinationPath);
    setGithubOutput('filename', safeFilename);

    console.log('\nProcess completed successfully.');

})().catch((err) => {
    console.error(`\nProcess failed: ${err.message}`);
    process.exit(1);
});
