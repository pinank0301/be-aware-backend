import { urlSchema } from "../schema/url-schema.js";
import ApiResponse from "../utils/api-response.js";
import AsyncHandler from "../utils/async-handler.js";
import { getWhoisInfo, getSSLDetails, getHostingDetails, takeScreenshot } from "../utils/scanner.js";
import { uploadOnCloudinary } from "../utils/cloudinary.js";
import { analyzeURL, calculateDomainAgeScore, calculateSSLScore, calculateHostingScore } from "../utils/url-analyzer.js";
import { URL } from "url";
import fs from "fs";

export const urlChecker = AsyncHandler(async (req, res) => {
    const parseResult = urlSchema.parse(req.body);
    const url = parseResult.url;

    if (!url) {
        throw new Error("URL is required");
    }

    console.log("Analyzing Url:", url);
    const parsedUrl = new URL(url.startsWith('http') ? url : `https://${url}`);
    const hostname = parsedUrl.hostname;

    // 1. Gather Technical Data
    // We add a screenshot step
    const [whois, ssl, hosting, screenshotPath] = await Promise.all([
        getWhoisInfo(hostname),
        getSSLDetails(hostname),
        getHostingDetails(hostname),
        takeScreenshot(url.startsWith('http') ? url : `https://${url}`)
    ]);

    // Upload screenshot to Cloudinary if available
    let screenshotUrl: string | null = null;
    let screenshotBase64: string | null = null;

    if (screenshotPath) {
        try {
            // Upload to Cloudinary
            screenshotUrl = await uploadOnCloudinary(screenshotPath);

            // Also read as base64 for AI vision analysis (before file is deleted by uploadOnCloudinary)
            if (fs.existsSync(screenshotPath)) {
                const imageBuffer = fs.readFileSync(screenshotPath);
                screenshotBase64 = imageBuffer.toString('base64');
            }
        } catch (error) {
            console.error("Failed to upload screenshot to Cloudinary:", error);
            // Clean up file if upload failed and file still exists
            if (fs.existsSync(screenshotPath)) {
                fs.unlinkSync(screenshotPath);
            }
        }
    }

    const technicalData = {
        url,
        hostname,
        whois,
        ssl,
        hosting,
        screenshot_available: !!screenshotUrl,
        screenshot_url: screenshotUrl || null // Always return screenshot_url or null
    };

    // 2. Analyze with Agent (Direct API call with Vision)
    const systemPrompt = `You are a cybersecurity expert specializing in phishing detection.
    Analyze the provided website data and screenshot to determine if it is Safe, Suspicious, or Dangerous.
    
    Focus on VISUAL IMPERSONATION:
    - Does the screenshot look like a major brand (Microsoft, Google, Bank, Netflix etc.)?
    - If yes, does the domain MATCH the official domain of that brand?
    - If it looks like a brand but the domain is unrelated, MARK AS DANGEROUS IMMEDIATELY.
    
    Also consider technical signals:
    - New domains (< 1 month) are suspicious.
    - Mismatched SSL issuers are suspicious.
    
    IMPORTANT: If you detect that this domain is trying to impersonate a legitimate brand/website, 
    you MUST provide the official/legitimate website URL in your response.
    
    OUTPUT JSON format with fields: 
    - result (safe/suspicious/dangerous)
    - reasons (array of strings)
    - legitimate_url (string, ONLY if impersonation detected - provide the FULL URL of the real website, e.g., "https://www.microsoft.com")
    - brand_name (string, ONLY if impersonation detected - the name of the brand being impersonated)`;

    const userContent: any[] = [
        { type: "text", text: `Analyze this website: ${url}\n\nTECHNICAL DATA:\n${JSON.stringify(technicalData, null, 2)}` }
    ];

    if (screenshotBase64) {
        userContent.push({
            type: "image_url",
            image_url: {
                url: `data:image/jpeg;base64,${screenshotBase64}`
            }
        });
    }

    let analysisResult;

    if (process.env.OPENAI_API_KEY) {
        try {
            const response = await fetch('https://api.openai.com/v1/chat/completions', {
                method: 'POST',
                headers: {
                    'Content-Type': 'application/json',
                    'Authorization': `Bearer ${process.env.OPENAI_API_KEY}`
                },
                body: JSON.stringify({
                    model: "gpt-4o", // gpt-4o has vision capabilities
                    messages: [
                        { role: "system", content: systemPrompt },
                        { role: "user", content: userContent }
                    ],
                    response_format: { type: "json_object" },
                    max_tokens: 1000
                })
            });

            const data = await response.json();
            if (data.choices && data.choices[0] && data.choices[0].message) {
                const content = data.choices[0].message.content;
                analysisResult = JSON.parse(content);
            } else {
                console.error("OpenAI API Error:", JSON.stringify(data, null, 2));
                if (data.error && data.error.code === 'insufficient_quota') {
                    analysisResult = {
                        error: "AI Analysis unavailable (OpenAI Quota Exceeded)",
                        details: "The system's AI analysis quota has been reached. Please contact support or check your OpenAI billing details."
                    };
                } else {
                    analysisResult = { error: "Failed to get analysis from AI", details: data };
                }
            }

        } catch (error) {
            console.error("AI Analysis Failed:", error);
            analysisResult = { error: "AI Analysis failed to execute" };
        }
    } else {
        analysisResult = { error: "OPENAI_API_KEY not configured" };
    }

    // FALLBACK: Simple heuristic detection if AI failed (for common brands)
    if (!analysisResult || analysisResult.error || !analysisResult.legitimate_url) {
        const lowerHostname = hostname.toLowerCase();

        const BRAND_MAP = [
            { name: "Microsoft", domain: "microsoft.com", patterns: ["microsoft", "rnicrosoft", "mircosoft", "microsft"] },
            { name: "Netflix", domain: "netflix.com", patterns: ["netflix", "n3tflix", "netflx"] },
            { name: "Google", domain: "google.com", patterns: ["google", "g00gle", "googl3"] },
            { name: "Amazon", domain: "amazon.com", patterns: ["amazon", "amzn"] },
            { name: "PayPal", domain: "paypal.com", patterns: ["paypal", "paypa1"] },
            { name: "Facebook", domain: "facebook.com", patterns: ["facebook", "fb."] },
            { name: "Instagram", domain: "instagram.com", patterns: ["instagram", "ig."] },
        ];

        for (const brand of BRAND_MAP) {
            const isMatch = brand.patterns.some(p => lowerHostname.includes(p) || url.toLowerCase().includes(p));
            const isOfficial = lowerHostname === brand.domain || lowerHostname.endsWith(`.${brand.domain}`);

            if (isMatch && !isOfficial) {
                console.log(`[Fallback] Detected potential impersonation of ${brand.name} in URL: ${url}`);
                analysisResult = {
                    ...analysisResult,
                    result: "dangerous",
                    brand_name: brand.name,
                    legitimate_url: `https://www.${brand.domain}`,
                    reasons: [
                        ...(analysisResult?.reasons || []),
                        `Potential impersonation of ${brand.name} detected by heuristic fallback (Hostname: ${hostname})`
                    ]
                };
                break;
            }
        }
    }

    // NEW: Capture legitimate website screenshot if AI detected impersonation
    let legitimateScreenshotUrl: string | null = null;
    let legitimateWebsiteInfo: { brand: string; url: string; screenshot_url: string | null } | null = null;

    if (analysisResult && analysisResult.legitimate_url && analysisResult.brand_name) {
        console.log(`AI detected impersonation of ${analysisResult.brand_name}. Capturing legitimate website screenshot...`);

        try {
            const legit_screenshot_path = await takeScreenshot(analysisResult.legitimate_url);
            if (legit_screenshot_path) {
                legitimateScreenshotUrl = await uploadOnCloudinary(legit_screenshot_path);
            }

            legitimateWebsiteInfo = {
                brand: analysisResult.brand_name,
                url: analysisResult.legitimate_url,
                screenshot_url: legitimateScreenshotUrl
            };
        } catch (error) {
            console.error("Failed to capture legitimate website screenshot:", error);
            // Still return the legitimate URL even if screenshot fails
            legitimateWebsiteInfo = {
                brand: analysisResult.brand_name,
                url: analysisResult.legitimate_url,
                screenshot_url: null
            };
        }
    }

    // Update technical_details with legitimate website info
    const updatedTechnicalData = {
        ...technicalData,
        legitimate_website: legitimateWebsiteInfo
    };

    // ===== COMPREHENSIVE SCORING SYSTEM =====

    // 1. URL Structure Analysis (20 points)
    const urlAnalysis = analyzeURL(url, hostname);

    // 2. Domain Age Analysis (20 points)
    const domainAgeScore = calculateDomainAgeScore(whois.creationDate);

    // 3. SSL Certificate Analysis (20 points)
    const sslScore = calculateSSLScore(ssl);

    // 4. Hosting Analysis (10 points)
    const hostingScore = calculateHostingScore(hosting);

    // 5. Visual Analysis from AI (30 points)
    let visualScore = { score: 15, max_score: 30, reason: 'AI analysis unavailable' };
    if (analysisResult && analysisResult.result) {
        const result = analysisResult.result.toLowerCase();
        if (result === 'safe') {
            visualScore = { score: 30, max_score: 30, reason: 'No brand impersonation or suspicious content detected' };
        } else if (result === 'suspicious') {
            visualScore = { score: 15, max_score: 30, reason: 'Some suspicious indicators detected' };
        } else if (result === 'dangerous') {
            visualScore = { score: 0, max_score: 30, reason: 'Visual impersonation or malicious content detected' };
        }
    }

    // Calculate total trust score (0-100)
    const trust_score = Math.min(100, Math.max(0,
        urlAnalysis.score +
        domainAgeScore.score +
        sslScore.score +
        hostingScore.score +
        visualScore.score
    ));

    // Determine overall result based on trust score
    let overallResult: 'safe' | 'suspicious' | 'dangerous';
    if (trust_score >= 70) {
        overallResult = 'safe';
    } else if (trust_score >= 40) {
        overallResult = 'suspicious';
    } else {
        overallResult = 'dangerous';
    }

    // Build key factors array
    const keyFactors: string[] = [];
    if (domainAgeScore.score >= 15) keyFactors.push(`Domain is well-established (${domainAgeScore.reason.split(' - ')[0]})`);
    if (domainAgeScore.score < 5) keyFactors.push(`⚠️ ${domainAgeScore.reason}`);
    if (sslScore.score === 20) keyFactors.push(`Valid SSL certificate from trusted authority`);
    if (sslScore.score === 0) keyFactors.push(`⚠️ ${sslScore.reason}`);
    if (urlAnalysis.score < 15) keyFactors.push(`⚠️ URL contains suspicious patterns`);
    if (visualScore.score === 30) keyFactors.push(`No visual impersonation detected`);
    if (visualScore.score === 0) keyFactors.push(`⚠️ ${visualScore.reason}`);

    // Combine all warnings
    const allWarnings = [
        ...urlAnalysis.issues,
        ...urlAnalysis.warnings,
        ...(analysisResult?.reasons || [])
    ];

    const finalResponse = {
        result: overallResult,
        trust_score,
        score_breakdown: {
            url_structure: {
                score: urlAnalysis.score,
                max_score: urlAnalysis.max_score,
                reason: urlAnalysis.issues.length > 0
                    ? urlAnalysis.issues.join('; ')
                    : 'URL structure appears normal',
                warnings: urlAnalysis.warnings
            },
            domain_age: {
                score: domainAgeScore.score,
                max_score: domainAgeScore.max_score,
                reason: domainAgeScore.reason
            },
            ssl_certificate: {
                score: sslScore.score,
                max_score: sslScore.max_score,
                reason: sslScore.reason
            },
            hosting: {
                score: hostingScore.score,
                max_score: hostingScore.max_score,
                reason: hostingScore.reason
            },
            visual_analysis: {
                score: visualScore.score,
                max_score: visualScore.max_score,
                reason: visualScore.reason,
                ai_reasons: analysisResult?.reasons || []
            }
        },
        key_factors: keyFactors,
        warnings: allWarnings,
        technical_details: updatedTechnicalData // Use updated data with legitimate website
    };

    return res.json(new ApiResponse(200, finalResponse, "Website genuineness analysis completed"))
})
