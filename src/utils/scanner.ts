import net from "node:net"
import tls from "node:tls"
import dns from "node:dns/promises"
import { URL } from "node:url"

const isVercel = !!process.env.VERCEL
const isRender = !!process.env.RENDER

interface WhoisInfo {
    raw: string
    domainName?: string | undefined
    registrar?: string | undefined
    creationDate?: string | undefined
    expirationDate?: string | undefined
}

interface SSLInfo {
    valid: boolean
    subject: any
    issuer: any
    validFrom: string
    validTo: string
    daysRemaining: number
}

interface HostingInfo {
    ip: string
    reverse?: string | undefined
}

/* ========================== WHOIS ========================== */

export async function getWhoisInfo(domain: string): Promise<WhoisInfo> {
    const parts = domain.split(".")
    const rootDomain = parts.length > 2 ? parts.slice(-2).join(".") : domain
    const tld = rootDomain.split(".").pop()

    let whoisServer = "whois.iana.org"
    if (tld === "com" || tld === "net") whoisServer = "whois.verisign-grs.com"
    else if (tld === "org") whoisServer = "whois.pir.org"
    else if (tld === "io") whoisServer = "whois.nic.io"

    return new Promise((resolve) => {
        const socket = net.createConnection(43, whoisServer, () => {
            socket.write(rootDomain + "\r\n")
        })

        let data = ""
        socket.on("data", (chunk) => (data += chunk))

        socket.on("end", () => {
            const info: WhoisInfo = { raw: data }

            const extract = (regex: RegExp) => data.match(regex)?.[1]?.trim()

            info.domainName = extract(/Domain Name:\s+(.+)/i) || undefined
            info.registrar = extract(/Registrar:\s+(.+)/i) || undefined
            info.creationDate = extract(/Creation Date:\s+(.+)/i) || undefined
            info.expirationDate = extract(/Registry Expiry Date:\s+(.+)/i) || undefined


            resolve(info)
        })

        socket.on("error", () => resolve({ raw: "Whois lookup failed" }))
        socket.setTimeout(5000, () => {
            socket.destroy()
            resolve({ raw: "Whois timeout" })
        })
    })
}

/* ========================== SSL ========================== */

export async function getSSLDetails(hostname: string): Promise<SSLInfo | null> {
    return new Promise((resolve) => {
        const socket = tls.connect(
            { host: hostname, port: 443, servername: hostname, rejectUnauthorized: false },
            () => {
                const cert = socket.getPeerCertificate()
                if (!cert || !cert.valid_to) {
                    socket.end()
                    resolve(null)
                    return
                }

                const validFrom = new Date(cert.valid_from)
                const validTo = new Date(cert.valid_to)
                const daysRemaining = Math.floor((+validTo - +new Date()) / 86400000)

                resolve({
                    valid: true,
                    subject: cert.subject,
                    issuer: cert.issuer,
                    validFrom: cert.valid_from,
                    validTo: cert.valid_to,
                    daysRemaining,
                })

                socket.end()
            }
        )

        socket.on("error", () => resolve(null))
        socket.setTimeout(5000, () => {
            socket.destroy()
            resolve(null)
        })
    })
}

/* ========================== HOSTING ========================== */

export async function getHostingDetails(hostname: string): Promise<HostingInfo | null> {
    try {
        const { address } = await dns.lookup(hostname)
        try {
            const reverse = (await dns.reverse(address))[0]
            return { ip: address, reverse }
        } catch {
            return { ip: address }
        }
    } catch {
        return null
    }
}

/* ========================== BROWSER ========================== */

async function getBrowser() {
    // VERCEL
    if (isVercel) {
        const chromium = (await import("@sparticuz/chromium-min")).default
        const puppeteer = await import("puppeteer-core")

        return puppeteer.launch({
            args: chromium.args,
            defaultViewport: chromium.defaultViewport,
            executablePath: await chromium.executablePath(),
            headless: chromium.headless,
        })
    }

    // RENDER + LOCAL
    const puppeteer = await import("puppeteer")

    return puppeteer.default.launch({
        headless: true,
        args: [
            "--no-sandbox",
            "--disable-setuid-sandbox",
            "--disable-dev-shm-usage",
            "--disable-gpu",
            "--hide-scrollbars",
        ],
    })
}

/* ========================== SCREENSHOT ========================== */

export async function takeScreenshot(url: string): Promise<string | null> {
    let browser

    try {
        const fs = await import("fs")
        const path = await import("path")

        browser = await getBrowser()
        const page = await browser.newPage()
        await page.setViewport({ width: 1280, height: 720 })

        const target = url.startsWith("http") ? url : `https://${url}`

        try {
            await page.goto(target, { waitUntil: ["load", "networkidle2"], timeout: 15000 })
        } catch (e: any) {
            if (e.message?.includes("ERR_NAME_NOT_RESOLVED")) return null
        }

        if (page.isClosed()) return null

        const tempDir = isVercel ? "/tmp" : path.join(process.cwd(), "temp")
        if (!fs.existsSync(tempDir)) fs.mkdirSync(tempDir, { recursive: true })

        const file = path.join(tempDir, `screenshot-${Date.now()}.jpg`)
        await page.screenshot({ path: file, type: "jpeg", quality: 60 })

        return file
    } catch {
        return null
    } finally {
        if (browser) {
            await browser.close().catch((err: unknown) => console.error("Close error:", err))
        }
    }
}
