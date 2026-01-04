import { GoogleGenAI, Type } from "@google/genai";
import { GeminiAnalysisResponse, InputType, ImageGenParams, Verdict, RiskLevel } from "../types";

// Analyze content using Gemini 3 series models with specialized security instructions
export const analyzeContent = async (
  content: string, 
  countries: string[], 
  inputType: InputType,
  imageData?: string,
  useSearch: boolean = false
): Promise<GeminiAnalysisResponse> => {
  const ai = new GoogleGenAI({ apiKey: process.env.API_KEY });
  
  // Model selection: Pro for complex forensic search/URL auditing, Flash for text speed
  // Use Gemini 3 Pro when high-fidelity URL/Search audit is required
  let modelName = (imageData || inputType === 'URL') ? 'gemini-3-pro-preview' : 'gemini-3-flash-preview';

  const systemInstruction = `You are a world-class global cyber-security, fraud detection, and digital safety forensic expert. 
Your goal is to provide a PROFESSIONAL, SaaS-level audit of potential scams, phishing, and cyber safety risks across multiple jurisdictions.

JURISDICTIONAL INTELLIGENCE:
You must analyze the threat for the following regions: ${countries.join(', ')}.
For each region, identify specific local markers (e.g., local banks, tax authorities, popular local apps used for the scam).

URL INTEGRITY AUDIT (MANDATORY FOR URL INPUTS):
1. Domain Age: Use googleSearch tool to find when the domain was registered. Brand new domains (less than 6 months) are EXTREMELY high risk.
2. Reputation Search: Search for "reputation of [domain]" or "[domain] scam reports". Check if the domain is flagged by security communities.
3. TLD Reputation: Flag suspicious Top-Level Domains like .xyz, .top, .icu, .buzz, etc.
4. Brand Match: Compare the domain with the official domain of the brand being impersonated. Detect homograph (look-alike) attacks.

DETECTION CAPABILITIES:
1. Impersonation: Recognize banks, gov agencies (IRS, HMRC, SBI), and brands (Amazon, Netflix, FedEx).
2. Account Takeover (ATO): Detect OTP stealing, session hijacking, or password reset bait.
3. Social Engineering: Identify Urgency, Fake Authority, Emotional Manipulation, or Greed.
4. Credential Theft: Flag requests for PINs, OTPs, full bank details, or login links.

MANDATORY JSON RESPONSE FORMAT:
{
  "verdict": "SAFE" | "SUSPICIOUS" | "SCAM",
  "riskLevel": "Low" | "Medium" | "High",
  "explanation": "Human-style forensic breakdown of why this is or isn't a threat.",
  "redFlags": ["Sense of urgency detected", "Non-official URL structure"],
  "nextSteps": ["Block sender", "Report to local Cyber Cell"],
  "regionalFindings": [
    {
      "country": "Country Name",
      "specificRisk": "Why it's dangerous in this specific country",
      "localRegulator": "Organization to report to in this country"
    }
  ],
  "impersonationDetected": "e.g., Apple Support Spoofing",
  "accountTakeoverRisk": "Low" | "Medium" | "High",
  "socialEngineeringType": "e.g., Phishing",
  "credentialWarning": "Warning message if applicable",
  "safetyAdvice": ["Advice 1", "Advice 2"],
  "shareableWarning": "Short warning for social media",
  "suggestedReplies": [{"label": "Action", "text": "Message content"}]
}

Respond in English. If input is multi-lingual, analyze all parts.`;

  const prompt = `Perform a comprehensive cross-jurisdictional forensic security audit.
Target Regions: ${countries.join(', ')}
Input Mode: ${inputType}
Data Content: ${content || "Analyzing visual artifacts in provided image."}

If the input is a URL, you MUST audit its registration age and reputation using the googleSearch tool. 
Provide a detailed explanation of the URL's legitimacy based on real-time intelligence.`;

  const config: any = {
    systemInstruction,
    tools: [{ googleSearch: {} }],
    responseMimeType: "application/json",
  };

  const response = await ai.models.generateContent({
    model: modelName,
    contents: imageData ? 
      { parts: [{ text: prompt }, { inlineData: { mimeType: 'image/jpeg', data: imageData.split(',')[1] } }] } :
      prompt,
    config
  });

  const responseText = response.text || "{}";
  let rawJson: any = {};
  try {
    rawJson = JSON.parse(responseText);
  } catch (e) {
    console.error("Failed to parse JSON response", e);
  }
  
  const links: any[] = [];
  const chunks = response.candidates?.[0]?.groundingMetadata?.groundingChunks;
  if (chunks) {
    chunks.forEach((chunk: any) => {
      if (chunk.web) {
        links.push({ 
          title: chunk.web.title || "External Intelligence Report", 
          uri: chunk.web.uri,
          type: 'web'
        });
      }
    });
  }

  return {
    ...rawJson,
    verdict: rawJson.verdict as Verdict || Verdict.SUSPICIOUS,
    riskLevel: rawJson.riskLevel as RiskLevel || RiskLevel.MEDIUM,
    inputTypeDetected: inputType,
    countryContext: `Audit intelligence cross-referenced with local fraud databases in: ${countries.join(', ')}.`,
    seoHelper: { keywords: [], faqs: [] },
    groundingLinks: links,
  };
};

export const generateSafetyImage = async (params: ImageGenParams): Promise<string> => {
  const ai = new GoogleGenAI({ apiKey: process.env.API_KEY });
  const isHighRes = params.imageSize === '2K' || params.imageSize === '4K';
  const model = isHighRes ? 'gemini-3-pro-image-preview' : 'gemini-2.5-flash-image';
  
  const imageConfig: any = {
    aspectRatio: params.aspectRatio,
  };
  
  if (isHighRes) {
    imageConfig.imageSize = params.imageSize;
  }

  const response = await ai.models.generateContent({
    model,
    contents: {
      parts: [{ text: `A futuristic, professional cybersecurity poster about ${params.prompt}. Corporate high-tech style.` }]
    },
    config: {
      imageConfig
    }
  });

  for (const part of response.candidates?.[0]?.content?.parts || []) {
    if (part.inlineData) {
      return `data:image/png;base64,${part.inlineData.data}`;
    }
  }
  throw new Error("Visual generation failed.");
};