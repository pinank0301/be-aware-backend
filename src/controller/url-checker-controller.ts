import { urlSchema } from "../schema/url-schema.js";
import ApiResponse from "../utils/api-response.js";
import AsyncHandler from "../utils/async-handler.js";
import { getWhoisInfo, getSSLDetails, getHostingDetails } from "../utils/scanner.js";
import { URL } from "url";

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
    const [whois, ssl, hosting] = await Promise.all([
        getWhoisInfo(hostname),
        getSSLDetails(hostname),
        getHostingDetails(hostname)
    ]);

    const technicalData = {
        url,
        hostname,
        whois,
        ssl,
        hosting
    };

    // 2. Analyze with Agent (Direct API call to avoid SDK issues)
    const prompt = `
    You are a cybersecurity expert analyzing a website for genuineness and trustworthiness.
    
    Here is the technical data gathered for the website: ${url}
    
    DATA:
    ${JSON.stringify(technicalData, null, 2)}
    
    TASK:
    Analyze this data to determine if the website is Safe, Suspicious, or Dangerous.
    Consider:
    - Domain Age (Creation Date vs Now). New domains are riskier.
    - SSL Certificate (Validity, Issuer, Type).
    - Hosting/IP reputation (if inferable, or just general consistency).
    - Consistency between domain name and content/registrar if clear.
    
    OUTPUT FORMAT:
    Return a JSON object with these keys:
    - score: (number 0-100, where 100 is very safe)
    - label: "Safe" | "Suspicious" | "Dangerous"
    - reasoning: (string, brief explanation of key factors)
    - key_issues: (array of strings, listing any red flags)
    
    Return ONLY valid JSON.
    `;

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
                    model: "gpt-4o",
                    messages: [{ role: "user", content: prompt }],
                    response_format: { type: "json_object" }
                })
            });

            const data = await response.json();
            if (data.choices && data.choices[0] && data.choices[0].message) {
                const content = data.choices[0].message.content;
                analysisResult = JSON.parse(content);
            } else {
                console.error("OpenAI API Error:", data);
                analysisResult = { error: "Failed to get analysis from AI" };
            }

        } catch (error) {
            console.error("AI Analysis Failed:", error);
            analysisResult = { error: "AI Analysis failed to execute" };
        }
    } else {
        analysisResult = { error: "OPENAI_API_KEY not configured" };
    }

    return res.json(new ApiResponse(200, {
        summary: analysisResult,
        details: technicalData
    }, "Website analysis completed"))
})
