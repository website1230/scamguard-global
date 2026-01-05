
export type RiskLevel = 'Low' | 'Medium' | 'High';
export type LayoutStatus = 'Passed' | 'Failed' | 'Suspicious' | 'N/A';

export interface TemplateAnomaly {
  x: number;
  y: number;
  width: number;
  height: number;
  label: string;
  severity: 'High' | 'Medium';
}

export interface ScanResult {
  riskLevel: RiskLevel;
  score: number;
  explanation: string;
  reasons: string[];
  advice: string[];
  layoutCheck?: LayoutStatus;
  anomalies?: TemplateAnomaly[];
}

export type ScanMode = 'text' | 'link' | 'image' | 'payment' | 'qr';

export type Country = string;

export type Language = {
  code: string;
  name: string;
  nativeName: string;
  flag: string;
};

export interface CountryInfo {
  name: string;
  code: string;
  region: string;
  flag: string;
}

export interface FAQItem {
  question: string;
  answer: string;
}

export type GeneratorTab = 'qr' | 'barcode' | 'bulk' | 'history';
export type ContentType = 'link' | 'text' | 'wifi' | 'whatsapp' | 'email';

export interface GeneratedCode {
  id: string;
  type: GeneratorTab;
  contentType: ContentType;
  value: string;
  timestamp: number;
  risk: RiskLevel;
  score: number;
}

export interface AnalysisOptions {
  urgencyWeight?: number;
  rewardWeight?: number;
  bankWeight?: number;
  otpWeight?: number;
  jobWeight?: number;
  linkWeight?: number;
  socialEngineeringWeight?: number;
  seoWeight?: number;
  deliveryWeight?: number;
  securityAlertWeight?: number;
  cryptoWeight?: number;
  romanceWeight?: number;
  immigrationWeight?: number;
}
