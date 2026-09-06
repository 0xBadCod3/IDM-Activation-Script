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
const OUTPUT_DIR = process.env.OUTPUT_DIR || path.resolve(__dirname, '..', '..', 'downloads');

const USERNAME = process.env.RINRU_USER || '';
const PASSWORD = process.env.RINRU_PASS || '';
const SAVED_COOKIE = process.env.RINRU_SESSION || '';
const COOKIE_OUTPUT_FILE = process.env.COOKIE_OUTPUT_FILE || '';

// --- GitHub Actions Secret Masking ---

/**
 * Registers a secret with GitHub Actions runner log scrubber so it is masked as ***.
 */
function maskSecretInActions(secret) {
    if (process.env.GITHUB_ACTIONS === 'true' && secret && typeof secret === 'string' && secret.length >= 6) {
        process.stdout.write(`::add-mask::${secret}\n`);
    }
}

// Mask known credentials immediately upon startup
if (PASSWORD) maskSecretInActions(PASSWORD);
if (USERNAME) maskSecretInActions(USERNAME);
if (SAVED_COOKIE) maskCookieValues(SAVED_COOKIE);

// Validate credentials if no saved session is provided
if (!SAVED_COOKIE && (!USERNAME || !PASSWORD)) {
    console.error('Error: RINRU_USER and RINRU_PASS env vars are required when RINRU_SESSION is not set.');
    process.exit(1);
}

if (!fs.existsSync(OUTPUT_DIR)) {
    fs.mkdirSync(OUTPUT_DIR, { recursive: true });
}

const UA = 'Mozilla/5.0 (Windows NT 10.0; Win64; x64) AppleWebKit/537.36 (KHTML, like Gecko) Chrome/124.0.0.0 Safari/537.36';
const MAX_RETRIES = 3;
const FORUM_HOST = 'cs.rin.ru';

// Shared in-memory cookie jar
let activeCookies = SAVED_COOKIE || '';

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
 * Finds the most relevant download link matching the target section keyword (e.g. 'Fix').
 */
function findBestDownloadLink(postHtml, sectionKeyword) {
    const allLinks = extractDownloadLinksFromPost(postHtml);
    if (allLinks.length === 0) return null;
    if (allLinks.length === 1) return allLinks[0];

    const kwLower = sectionKeyword.toLowerCase();

    // 1. Direct match on anchor text / attachment filename (e.g. "IDM_6.42_Fix.rar")
    const anchorMatch = allLinks.find(l => l.anchorText.toLowerCase().includes(kwLower));
    if (anchorMatch) {
        console.log(`    Matched link by filename/anchor text: "${anchorMatch.anchorText}"`);
        return anchorMatch;
    }

    // 2. Section heading match: find heading containing keyword, then look for links in that section
    const headingRegex = /<(?:b|strong|span|h[1-6])\b[^>]*>([\s\S]*?)<\/(?:b|strong|span|h[1-6])>/gi;
    let h;
    while ((h = headingRegex.exec(postHtml)) !== null) {
        const headingText = stripHtml(h[1]).toLowerCase();
        if (headingText.includes(kwLower)) {
            const headingPos = h.index;
            // Search within next 3000 chars after the section header
            const subHtml = postHtml.substring(headingPos, headingPos + 3000);
            const subLinks = extractDownloadLinksFromPost(subHtml);
            if (subLinks.length > 0) {
                console.log(`    Matched link in section heading "${stripHtml(h[1])}" -> file ID ${subLinks[0].id}`);
                return subLinks[0];
            }
        }
    }

    // 3. Text proximity fallback
    const text = stripHtml(postHtml).toLowerCase();
    const kwIdx = text.indexOf(kwLower);
    if (kwIdx !== -1) {
        let bestDist = Infinity;
        let bestProximityLink = allLinks[0];
        for (const link of allLinks) {
            const textBefore = stripHtml(postHtml.substring(0, link.index)).toLowerCase();
            const dist = Math.abs(textBefore.length - kwIdx);
            if (dist < bestDist) {
                bestDist = dist;
                bestProximityLink = link;
            }
        }
        console.log(`    Matched link by proximity to "${sectionKeyword}" -> file ID ${bestProximityLink.id}`);
        return bestProximityLink;
    }

    // Default fallback to first link
    return allLinks[0];
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
 */
async function findDownloadLink() {
    console.log(`\nNavigating topic: ${TOPIC_URL}`);
    console.log(`Target Author: "${POST_AUTHOR}" | Section: "${SECTION_KEYWORD}"`);

    const parsed = new URL(TOPIC_URL);
    const f = parsed.searchParams.get('f') || '14';
    const t = parsed.searchParams.get('t') || '27045';
    const initialStart = parseInt(parsed.searchParams.get('start'), 10) || 0;

    let start = initialStart;
    let perPage = 15;
    let maxStart = initialStart;
    let pagesChecked = 0;
    const MAX_PAGES_TO_SCAN = 60;

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
            console.log(`  Found ${authorPosts.length} post(s) by "${POST_AUTHOR}" on this page.`);

            // Search through author's posts for the section & download link
            for (const post of authorPosts) {
                const bestLink = findBestDownloadLink(post.html, SECTION_KEYWORD);
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

    console.error(`\nError: Could not find download link by author "${POST_AUTHOR}" for section "${SECTION_KEYWORD}".`);
    process.exit(1);
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

                // Export output for GitHub Actions workflow chaining
                if (process.env.GITHUB_OUTPUT) {
                    try {
                        fs.appendFileSync(
                            process.env.GITHUB_OUTPUT,
                            `downloaded_file=${destinationPath}\nfilename=${safeFilename}\n`
                        );
                    } catch {
                        // Ignore if running outside GHA
                    }
                }

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
    // Step 1: Attempt to use saved session cookie if available
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

    // Step 2: Authenticate if no active session
    if (!sessionValid) {
        if (!USERNAME || !PASSWORD) {
            console.error('Error: Session cookie expired and no RINRU_USER / RINRU_PASS provided for re-login.');
            process.exit(1);
        }
        await passSecurityCheck();
        await login();
    }

    // Step 3: Locate the target download URL from topic
    const downloadUrl = await findDownloadLink();

    // Step 4: Download and save the file safely
    console.log(`\nInitiating file download: ${downloadUrl}`);
    await downloadFile(downloadUrl);

})().catch((err) => {
    console.error(`\nProcess failed: ${err.message}`);
    process.exit(1);
});
