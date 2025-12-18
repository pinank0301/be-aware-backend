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
export declare function getWhoisInfo(domain: string): Promise<WhoisInfo>;
export declare function getSSLDetails(hostname: string): Promise<SSLInfo | null>;
export declare function getHostingDetails(hostname: string): Promise<HostingInfo | null>;
export {};
//# sourceMappingURL=scanner.d.ts.map