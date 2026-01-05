
import { GoogleGenAI, Type } from "@google/genai";
import { ScanResult, RiskLevel, Country, ScanMode, LayoutStatus, TemplateAnomaly } from './types';

// Baseline metrics for popular payment apps
const PLATFORM_TEMPLATES: Record<string, any> = {
  'Google Pay': { 
    primaryColor: '#4285F4', 
    aspectRatios: [19.5/9, 20/9, 16/9],
    fontFamily: 'Product Sans / Google Sans',
    branding: 'Google Logo top center/left',
    structure: 'Clean material design, pill buttons'
  },
  'PhonePe': { 
    primaryColor: '#5f259f', 
    aspectRatios: [19.5/9, 20/9],
    fontFamily: 'Roboto / Custom Sans',
    branding: 'Purple header gradient',
    structure: 'Transaction ID at bottom, large checkmark'
  },
  'Paytm': { 
    primaryColor: '#00baf2', 
    aspectRatios: [19.5/9, 20/9, 18/9],
    fontFamily: 'Paytm Sans / Inter',
    branding: 'Light blue accents',
    structure: 'Payment Success badge top, order details below'
  },
  'PayPal': { 
    primaryColor: '#003087', 
    aspectRatios: [16/9, 19.5/9],
    fontFamily: 'PayPal Sans / Futura',
    branding: 'Double P logo top center',
    structure: 'Minimalist, center-aligned transaction amount'
  },
};

/**
 * AI-powered analysis for text content
 */
export const analyzeText = async (text: string, country: Country): Promise<ScanResult> => {
  if (!text.trim()) {
    return { riskLevel: 'Low', score: 0, explanation: "Please enter a message.", reasons: [], advice: [] };
  }

  try {
    const ai = new GoogleGenAI({ apiKey: process.env.API_KEY });
    const prompt = `Analyze this message for scam indicators in ${country}. Message: "${text}"`;

    const response = await ai.models.generateContent({
      model: 'gemini-3-flash-preview',
      contents: prompt,
      config: { 
        responseMimeType: 'application/json',
        responseSchema: {
          type: Type.OBJECT,
          properties: {
            score: { type: Type.INTEGER },
            explanation: { type: Type.STRING },
            reasons: { type: Type.ARRAY, items: { type: Type.STRING } },
            advice: { type: Type.ARRAY, items: { type: Type.STRING } }
          },
          required: ["score", "explanation", "reasons", "advice"],
        }
      }
    });

    const aiResult = JSON.parse(response.text || '{}');
    const finalScore = aiResult.score || 0;
    const riskLevel: RiskLevel = finalScore > 70 ? 'High' : (finalScore > 35 ? 'Medium' : 'Low');
    
    return {
      riskLevel,
      score: Math.min(finalScore, 100),
      explanation: aiResult.explanation,
      reasons: aiResult.reasons,
      advice: aiResult.advice
    };
  } catch (error) {
    return { riskLevel: 'Low', score: 0, explanation: "Analysis failed.", reasons: [], advice: [] };
  }
};

/**
 * Analysis for links/URLs
 */
export const analyzeLink = async (url: string, country: Country): Promise<ScanResult> => {
  try {
    const ai = new GoogleGenAI({ apiKey: process.env.API_KEY });
    const response = await ai.models.generateContent({
      model: 'gemini-3-flash-preview',
      contents: `Evaluate risk for URL: ${url} in ${country}`,
      config: { 
        responseMimeType: 'application/json',
        responseSchema: {
          type: Type.OBJECT,
          properties: {
            score: { type: Type.INTEGER },
            reasons: { type: Type.ARRAY, items: { type: Type.STRING } }
          },
          required: ["score", "reasons"],
        }
      }
    });
    const aiResult = JSON.parse(response.text || '{}');
    const score = aiResult.score || 0;
    return {
      riskLevel: score > 70 ? 'High' : (score > 35 ? 'Medium' : 'Low'),
      score,
      explanation: `Domain audit complete for ${url}.`,
      reasons: aiResult.reasons,
      advice: ["Check for subtle misspellings in the URL."]
    };
  } catch (e) {
    return { riskLevel: 'Low', score: 0, explanation: "Link analysis failed.", reasons: [], advice: [] };
  }
};

/**
 * Advanced Forensic analysis for images/receipts using Computer Vision
 */
export const analyzeForensics = async (
  mode: ScanMode, 
  metadata: any, 
  imageSize: { width: number, height: number }, 
  country: Country, 
  platform: string = 'General',
  base64Image?: string
): Promise<ScanResult> => {
  let score = 0;
  const reasons: string[] = [];
  const anomalies: TemplateAnomaly[] = [];
  let layoutCheck: LayoutStatus = 'N/A';
  
  // 1. Initial Metadata Audit
  if (metadata) {
    if (metadata.software) {
      const manipulationTools = /photoshop|canva|picsart|snapseed|editor|paint|express/i;
      if (manipulationTools.test(metadata.software)) {
        score += 40;
        reasons.push(`Modification Signature: File processed via ${metadata.software}.`);
      }
    }
    
    if (metadata.isAlteredTimestamp) {
      score += 30;
      reasons.push("Epoch Discrepancy: Metadata suggests creation date was altered post-capture.");
    }

    if (metadata.hasExif && metadata.isScreenshot && (metadata.make || metadata.model)) {
      score += 15;
      reasons.push("Inconsistent Metadata: File claims to be a screenshot but contains camera lens data.");
    }

    if (metadata.gpsLatitude !== undefined) {
      reasons.push(`Geolocation Marker Found: ${metadata.gpsLatitude.toFixed(2)}, ${metadata.gpsLongitude.toFixed(2)}`);
    }
  }

  // 2. Structural Aspect Ratio Audit
  const template = PLATFORM_TEMPLATES[platform];
  if (template) {
    const ratio = imageSize.height / imageSize.width;
    const isStandard = template.aspectRatios.some((r: number) => Math.abs(ratio - r) < 0.1);
    if (!isStandard) {
      score += 20;
      reasons.push(`Geometric Mismatch: Screenshot dimensions do not match the ${platform} standard.`);
    }
  }

  // 3. AI Vision Audit (Deep Inspection for UI Layout)
  if (base64Image) {
    try {
      const ai = new GoogleGenAI({ apiKey: process.env.API_KEY });
      const base64Data = base64Image.split(',')[1];
      
      const response = await ai.models.generateContent({
        model: 'gemini-3-flash-preview',
        contents: {
          parts: [
            { inlineData: { data: base64Data, mimeType: 'image/jpeg' } },
            { text: `Forensically analyze this ${platform} payment screenshot for fraud markers. 
                    Compare it against the official UI template of ${platform}.
                    Target checks:
                    1. Font Consistency: Check for mismatched weights, sizes, or non-system fonts.
                    2. Spacing & Alignment: Identify misaligned text blocks, irregular padding, or overlapping UI elements.
                    3. Color Patterns: Verify branding hex codes and gradients.
                    4. UI Structure: Look for missing Transaction IDs, forged checkmarks, or irregular date formats for ${country}.
                    
                    Return findings as JSON. Categorize the layout check as: Passed, Failed, or Suspicious.` }
          ]
        },
        config: { 
          responseMimeType: 'application/json',
          responseSchema: {
            type: Type.OBJECT,
            properties: {
              aiScore: { type: Type.INTEGER },
              aiReasons: { type: Type.ARRAY, items: { type: Type.STRING } },
              aiExplanation: { type: Type.STRING },
              layoutStatus: { type: Type.STRING, description: "Must be one of: Passed, Failed, Suspicious" },
              detectedAnomalies: {
                type: Type.ARRAY,
                items: {
                  type: Type.OBJECT,
                  properties: {
                    x: { type: Type.NUMBER },
                    y: { type: Type.NUMBER },
                    width: { type: Type.NUMBER },
                    height: { type: Type.NUMBER },
                    label: { type: Type.STRING },
                    severity: { type: Type.STRING }
                  },
                  required: ["x", "y", "width", "height", "label", "severity"]
                }
              }
            },
            required: ["aiScore", "aiReasons", "aiExplanation", "detectedAnomalies", "layoutStatus"],
          }
        }
      });

      const aiResult = JSON.parse(response.text || '{}');
      score = Math.max(score, aiResult.aiScore || 0);
      reasons.push(...(aiResult.aiReasons || []));
      anomalies.push(...(aiResult.detectedAnomalies || []));
      layoutCheck = (aiResult.layoutStatus as LayoutStatus) || 'Suspicious';
      
      return {
        riskLevel: score > 70 ? 'High' : (score > 35 ? 'Medium' : 'Low'),
        score: Math.min(score, 100),
        explanation: aiResult.aiExplanation || "Forensic vision audit complete.",
        reasons: [...new Set(reasons)],
        advice: [
          "Cross-verify this Transaction ID in your banking app.",
          "Check for blurred edges around the currency symbol.",
          "Check if the fonts are consistent across the entire screen."
        ],
        anomalies,
        layoutCheck
      };
    } catch (e) {
      console.error("AI Forensic Vision failed:", e);
    }
  }

  // Fallback heuristic for layoutCheck if AI fails
  if (layoutCheck === 'N/A') {
    layoutCheck = score > 60 ? 'Failed' : (score > 25 ? 'Suspicious' : 'Passed');
  }

  return {
    riskLevel: score > 65 ? 'High' : (score > 30 ? 'Medium' : 'Low'),
    score: Math.min(score, 100),
    explanation: "Basic heuristic forensic audit complete.",
    reasons: [...new Set(reasons)],
    advice: ["Verify the transaction manually.", "Check for editing artifacts."],
    anomalies,
    layoutCheck
  };
};
