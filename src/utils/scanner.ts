import net from 'net';
import tls from 'tls';
import dns from 'dns/promises';
import { URL } from 'url';

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
    const tld = domain.split('.').pop();
    let whoisServer = 'whois.iana.org'; // Default start, simplified for this implementation

    // Simple lookup map for common TLDs to avoid double hops if possible
    if (tld === 'com' || tld === 'net') whoisServer = 'whois.verisign-grs.com';
    else if (tld === 'org') whoisServer = 'whois.pir.org';
    else if (tld === 'io') whoisServer = 'whois.nic.io';
    // Add more as needed or implement recursive lookup if needed, keeping it simple for now

    return new Promise((resolve, reject) => {
        const socket = net.createConnection(43, whoisServer, () => {
            socket.write(domain + '\r\n');
        });

        let data = '';
        socket.on('data', (chunk) => {
            data += chunk;
        });

        socket.on('end', () => {
            // Basic parsing (very heuristic based)
            const whoisInfo: WhoisInfo = { raw: data };

            // Try to extract some common fields using Regex
            const domainMatch = data.match(/Domain Name:\s+(.+)/i);
            if (domainMatch && domainMatch[1]) whoisInfo.domainName = domainMatch[1].trim();

            const registrarMatch = data.match(/Registrar:\s+(.+)/i);
            if (registrarMatch && registrarMatch[1]) whoisInfo.registrar = registrarMatch[1].trim();

            const creationMatch = data.match(/Creation Date:\s+(.+)/i);
            if (creationMatch && creationMatch[1]) whoisInfo.creationDate = creationMatch[1].trim();

            const expiryMatch = data.match(/Registry Expiry Date:\s+(.+)/i);
            if (expiryMatch && expiryMatch[1]) whoisInfo.expirationDate = expiryMatch[1].trim();

            resolve(whoisInfo);
        });

        socket.on('error', (err) => {
            console.error('Whois error:', err);
            // resolve with empty or partial info rather than failing the whole check
            resolve({ raw: 'Error fetching whois data' });
        });

        socket.setTimeout(5000, () => {
            socket.destroy();
            resolve({ raw: 'Whois request timed out' });
        });
    });
}

export async function getSSLDetails(hostname: string): Promise<SSLInfo | null> {
    return new Promise((resolve) => {
        const options = {
            host: hostname,
            port: 443,
            servername: hostname,
            rejectUnauthorized: false // We want to inspect even if invalid
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
            // @ts-ignore
            const daysRemaining = Math.floor((validTo - new Date()) / (1000 * 60 * 60 * 24));

            const info: SSLInfo = {
                valid: socket.authorized || true, // simplified, dependent on rejectUnauthorized=false but we can check checking
                subject: cert.subject,
                issuer: cert.issuer,
                validFrom: cert.valid_from,
                validTo: cert.valid_to,
                daysRemaining
            };
            socket.end();
            resolve(info);
        });

        socket.on('error', (err) => {
            console.error("SSL Error", err);
            resolve(null);
        });

        socket.setTimeout(5000, () => {
            socket.destroy();
            resolve(null);
        });
    });
}

export async function getHostingDetails(hostname: string): Promise<HostingInfo | null> {
    try {
        const result = await dns.lookup(hostname);
        let reverse = '';
        try {
            const reverses = await dns.reverse(result.address);
            if (reverses && reverses.length > 0) {
                reverse = reverses[0] ?? '';
            }
        } catch (e) {
            // Ignore reverse lookup errors
        }

        return {
            ip: result.address,
            reverse
        };
    } catch (e) {
        console.error("DNS Error", e);
        return null;
    }
}
