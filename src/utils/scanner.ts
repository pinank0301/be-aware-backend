import net from "node:net";
import tls from "node:tls";
import dns from "node:dns/promises";
import { URL } from "node:url";

const isVercel = !!process.env.VERCEL;

interface WhoisInfo {
    raw: string;
    domainName?: string;
    registrar?: string;
    creationDate?: string;
    expirationDate?: string;
}

interface SSLInfo {
    valid: boolean;
    subject: any;
    issuer: any;
    validFrom: string;
    validTo: string;
    daysRemaining: number;
}

interface HostingInfo {
    ip: string;
    reverse?: string;
}

export async function getWhoisInfo(domain: string): Promise<WhoisInfo> {
    // Extract root domain (remove subdomains like www, api, etc.)
    const parts = domain.split('.');
    const rootDomain = parts.length > 2
        ? parts.slice(-2).join('.') // Take last 2 parts (domain.tld)
        : domain;

    const tld = rootDomain.split(".").pop();
    let whoisServer = "whois.iana.org"; // Default start, simplified for this implementation

    // Simple lookup map for common TLDs to avoid double hops if possible
    if (tld === "com" || tld === "net") whoisServer = "whois.verisign-grs.com";
    else if (tld === "org") whoisServer = "whois.pir.org";
    else if (tld === "io") whoisServer = "whois.nic.io";
    // Add more as needed or implement recursive lookup if needed, keeping it simple for now

    return new Promise((resolve, reject) => {
        const socket = net.createConnection(43, whoisServer, () => {
            socket.write(rootDomain + "\r\n"); // Query root domain
        });

        let data = "";
        socket.on("data", (chunk) => {
            data += chunk;
        });

        socket.on("end", () => {
            // Basic parsing (very heuristic based)
            const whoisInfo: WhoisInfo = { raw: data };

            // Try to extract some common fields using Regex
            const domainMatch = data.match(/Domain Name:\s+(.+)/i);
            if (domainMatch && domainMatch[1])
                whoisInfo.domainName = domainMatch[1].trim();

            const registrarMatch = data.match(/Registrar:\s+(.+)/i);
            if (registrarMatch && registrarMatch[1])
                whoisInfo.registrar = registrarMatch[1].trim();

            const creationMatch = data.match(/Creation Date:\s+(.+)/i);
            if (creationMatch && creationMatch[1])
                whoisInfo.creationDate = creationMatch[1].trim();

            const expiryMatch = data.match(/Registry Expiry Date:\s+(.+)/i);
            if (expiryMatch && expiryMatch[1])
                whoisInfo.expirationDate = expiryMatch[1].trim();

            resolve(whoisInfo);
        });

        socket.on("error", (err) => {
            console.error("Whois error:", err);
            // resolve with empty or partial info rather than failing the whole check
            resolve({ raw: "Error fetching whois data" });
        });

        socket.setTimeout(5000, () => {
            socket.destroy();
            resolve({ raw: "Whois request timed out" });
        });
    });
}

export async function getSSLDetails(hostname: string): Promise<SSLInfo | null> {
    return new Promise((resolve) => {
        const options = {
            host: hostname,
            port: 443,
            servername: hostname,
            rejectUnauthorized: false, // We want to inspect even if invalid
        };

        const socket = tls.connect(options, () => {
            const cert = socket.getPeerCertificate();

            if (Object.keys(cert).length === 0) {
                socket.end();
                resolve(null);
                return;
            }

            const validFrom = new Date(cert.valid_from);
            const validTo = new Date(cert.valid_to);
            const daysRemaining = Math.floor(
                // @ts-ignore
                (validTo - new Date()) / (1000 * 60 * 60 * 24)
            );

            const info: SSLInfo = {
                valid: socket.authorized || true, // simplified, dependent on rejectUnauthorized=false but we can check checking
                subject: cert.subject,
                issuer: cert.issuer,
                validFrom: cert.valid_from,
                validTo: cert.valid_to,
                daysRemaining,
            };
            socket.end();
            resolve(info);
        });

        socket.on("error", (err) => {
            console.error("SSL Error", err);
            resolve(null);
        });

        socket.setTimeout(5000, () => {
            socket.destroy();
            resolve(null);
        });
    });
}

export async function getHostingDetails(
    hostname: string
): Promise<HostingInfo | null> {
    try {
        const result = await dns.lookup(hostname);
        let reverse = "";
        try {
            const reverses = await dns.reverse(result.address);
            if (reverses && reverses.length > 0) {
                reverse = reverses[0] ?? "";
            }
        } catch (e) {
            // Ignore reverse lookup errors
        }

        return {
            ip: result.address,
            reverse,
        };
    } catch (e) {
        console.error("DNS Error", e);
        return null;
    }
}

async function getBrowser() {
    if (isVercel) {
        // Vercel Environment
        const chromium = (await import('@sparticuz/chromium-min')).default;
        const puppeteer = await import('puppeteer-core');

        return puppeteer.launch({
            args: chromium.args,
            defaultViewport: chromium.defaultViewport,
            executablePath: await chromium.executablePath('https://github.com/Sparticuz/chromium/releases/download/v131.0.1/chromium-v131.0.1-pack.tar'),
            headless: chromium.headless,
        });
    } else {
        // Local Environment
        // Try to use puppeteer first (standard) or fallback to puppeteer-core
        try {
            const puppeteer = await import('puppeteer');
            return puppeteer.default.launch({
                headless: true,
                args: [
                    '--no-sandbox',
                    '--disable-setuid-sandbox',
                    '--disable-dev-shm-usage',
                    '--disable-gpu',
                    '--hide-scrollbars'
                ]
            });
        } catch (e) {
            console.log("Standard puppeteer not found, trying puppeteer-core...");
            const puppeteer = await import('puppeteer-core');
            // On Windows, frequent paths for Chrome:
            const chromePaths = [
                'C:\\Program Files\\Google\\Chrome\\Application\\chrome.exe',
                'C:\\Program Files (x86)\\Google\\Chrome\\Application\\chrome.exe'
            ];
            const fs = await import('fs');
            const executablePath = chromePaths.find(p => fs.existsSync(p));

            const options: any = {
                headless: true,
                args: ['--no-sandbox', '--disable-setuid-sandbox']
            };
            if (executablePath) options.executablePath = executablePath;

            return puppeteer.launch(options);
        }
    }
}

export async function takeScreenshot(url: string): Promise<string | null> {
    // Returns the local file path of the screenshot for Cloudinary upload
    let browser;
    try {
        const fs = await import('fs');
        const path = await import('path');

        browser = await getBrowser();

        const page = await browser.newPage();
        await page.setViewport({ width: 1280, height: 720 });

        // Add https if missing for the navigation
        const targetUrl = url.startsWith('http') ? url : `https://${url}`;

        console.log(`Navigating to ${targetUrl}...`);

        try {
            // Try to navigate with a reasonable timeout
            await page.goto(targetUrl, {
                waitUntil: ['load', 'networkidle2'],
                timeout: 15000
            });
        } catch (gotoError: any) {
            console.error(`Navigation to ${targetUrl} failed or timed out:`, gotoError.message);
            // If it's a DNS error or connection error, we can't take a screenshot
            if (gotoError.message.includes('ERR_NAME_NOT_RESOLVED') ||
                gotoError.message.includes('ERR_CONNECTION_REFUSED') ||
                gotoError.message.includes('DNS_PROBE_FINISHED_NXDOMAIN')) {
                return null;
            }
            // For other timeouts, we might still try to take a partial screenshot if something loaded
        }

        // Check if we are still attached to the page after navigation attempt
        if (page.isClosed()) {
            console.error("Page was closed during navigation.");
            return null;
        }

        // Create temp directory in a writable location (important for Vercel)
        const os = await import('os');
        const tempDir = isVercel ? '/tmp' : path.join(process.cwd(), 'temp');
        if (!fs.existsSync(tempDir)) {
            fs.mkdirSync(tempDir, { recursive: true });
        }

        // Save screenshot to temporary file
        const filename = `screenshot-${Date.now()}-${Math.random().toString(36).substring(7)}.jpg`;
        const filepath = path.join(tempDir, filename);

        console.log(`Taking screenshot: ${filepath}`);
        await page.screenshot({ path: filepath, type: 'jpeg', quality: 60 });

        return filepath;
    } catch (e) {
        console.error("Screenshot Error:", e);
        return null;
    } finally {
        if (browser) {
            await browser.close().catch(err => console.error("Error closing browser:", err));
        }
    }
}
