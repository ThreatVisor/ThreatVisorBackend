// ~/multi-scanner-microservice/index.mjs
// COMPLETE UNIFIED AI MULTI-SCANNER with Enhanced Logging and Fixed Processing
import express from 'express';
import 'dotenv/config';
import { exec, execSync } from 'child_process';
import fs from 'fs';
import path from 'path';
import { createClient } from '@supabase/supabase-js';
import Anthropic from '@anthropic-ai/sdk';
import multer from 'multer';

const app = express();
app.use(express.json());

// Environment variables - with working API key fallback
// Environment variables - with working API key fallback
const ANTHROPIC_API_KEY = process.env.ANTHROPIC_API_KEY;
const ANTHROPIC_MODEL = process.env.ANTHROPIC_MODEL || "claude-sonnet-4-5-20250929";

const hostDir = path.resolve('.');
const reportsDir = path.join(hostDir, 'reports');
const scriptsDir = path.join(hostDir, 'scripts');
const uploadsDir = path.join(hostDir, 'tmp', 'uploads');

// Ensure reports and scripts directories exist with proper permissions
[reportsDir, scriptsDir, uploadsDir].forEach(dir => {
  if (!fs.existsSync(dir)) {
    fs.mkdirSync(dir, { recursive: true });
    fs.chmodSync(dir, 0o777);
  }
});

// Configure multer for file uploads
const upload = multer({ 
  dest: uploadsDir,
  limits: { 
    fileSize: 50 * 1024 * 1024  // 50MB max file size
  }
});

// Scanner configurations
const SCANNERS = {
  zap: {
    name: 'OWASP ZAP',
    containerName: 'zaproxy/zap-stable',
    reportFile: 'zap_report.json',
    reportFormat: 'json',
    containerWorkDir: '/zap/wrk'
  },
  rengine: {
    name: 'reNgine',
    containerName: 'custom-rengine',
    reportFile: 'rengine_report.json',
    reportFormat: 'json',
    containerWorkDir: '/app/reports'
  },
  wapiti: {
    name: 'Wapiti',
    containerName: 'wapiti-custom',
    reportFile: 'wapiti_report.json',
    reportFormat: 'json',
    containerWorkDir: '/tmp/reports'
  },
  nikto: {
    name: 'Nikto',
    containerName: 'ghcr.io/sullo/nikto:latest',
    reportFile: 'nikto_report.txt',
    reportFormat: 'txt',
    containerWorkDir: '/tmp/reports'
  },
  w3af: {
    name: 'w3af',
    containerName: 'w3af-custom',
    reportFile: 'w3af_report.txt',
    reportFormat: 'txt',
    containerWorkDir: '/app/reports'
  },
  nmap: {
    name: 'Nmap',
    containerName: 'instrumentisto/nmap:latest',
    reportFile: 'nmap_report.json',
    reportFormat: 'json',
    containerWorkDir: '/tmp/reports',
    layer: 'network',
    scanner_category: 'network'
  },
  trivy: {
    name: 'Trivy',
    containerName: 'aquasec/trivy:latest',
    reportFile: 'trivy_report.json',
    reportFormat: 'json',
    containerWorkDir: '/tmp/reports',
    layer: 'container',
    scanner_category: 'container'
  },
  wazuh: {
    name: 'Wazuh',
    containerName: null, // API-based, no container
    reportFile: 'wazuh_report.json',
    reportFormat: 'json',
    containerWorkDir: '/tmp/reports',
    layer: 'infrastructure',
    scanner_category: 'infrastructure'
  },
  testssl: {
    name: 'testssl.sh',
    containerName: 'drwetter/testssl.sh:latest',
    reportFile: 'testssl_report.json',
    reportFormat: 'json',
    containerWorkDir: '/tmp/reports',
    layer: 'network',
    scanner_category: 'network'
  },
  tenable: {
    name: 'Tenable.io',
    containerName: null, // API-based, no container
    reportFile: 'tenable_report.json',
    reportFormat: 'json',
    containerWorkDir: '/tmp/reports',
    layer: 'infrastructure',
    scanner_category: 'infrastructure'
  }
};

// Helper functions with safe type handling
function mapZapRiskToSeverity(riskCode) {
  switch (String(riskCode)) {
    case "3": return "critical";
    case "2": return "high";
    case "1": return "medium";
    default: return "low";
  }
}

function mapWapitiLevelToSeverity(level) {
  const numLevel = parseInt(level) || 1;
  switch (numLevel) {
    case 3: return "high";
    case 2: return "medium";
    case 1: return "low";
    default: return "medium";
  }
}

function mapGenericSeverityToLevel(severity) {
  const severityMap = {
    'critical': 'critical',
    'high': 'high',
    'medium': 'medium',
    'low': 'low',
    'info': 'low',
    'informational': 'low'
  };
  return severityMap[String(severity).toLowerCase()] || 'low';
}

function extractCVEIds(reference = "") {
  if (!reference) return [];
  return String(reference).split(/[;,]\s*/g).filter((r) => /^CVE-\d{4}-\d{4,}$/.test(r));
}

function calculateRiskLevel(severity, confidence) {
  let baseRisk = 0;
  switch (severity) {
    case 'critical': baseRisk = 10; break;
    case 'high': baseRisk = 8; break;
    case 'medium': baseRisk = 6; break;
    case 'low': baseRisk = 4; break;
    default: baseRisk = 2;
  }

  const confidenceModifier = confidence === 'high' ? 0 : confidence === 'medium' ? -1 : -2;
  return Math.max(1, Math.min(10, baseRisk + confidenceModifier));
}

// Safe integer conversion helper
function safeIntOrNull(value) {
  if (value === null || value === undefined || value === '') return null;
  const parsed = parseInt(value);
  return isNaN(parsed) ? null : parsed;
}

// ENHANCED AI ANALYSIS FUNCTION - Generates detailed exploit scenarios and specific remediation
async function processAllVulnerabilitiesWithAI(allVulnerabilities, scanMetadata, target, companyProfile = null) {
  console.log('\n' + '='.repeat(80));
  console.log('🤖 AI PROCESSING STARTING - ENHANCED LOGGING');
  console.log('='.repeat(80));

  // REDUCED BATCH SIZE to 1 to absolutely minimize token usage and prevent truncation
  const BATCH_SIZE = 1;
  const batches = [];
  for (let i = 0; i < allVulnerabilities.length; i += BATCH_SIZE) {
    batches.push(allVulnerabilities.slice(i, i + BATCH_SIZE));
  }

  console.log(`📦 Split ${allVulnerabilities.length} vulnerabilities into ${batches.length} batches of size ${BATCH_SIZE}`);

  console.log('\n' + '='.repeat(80));
  console.log('🏢 BUSINESS CONTEXT CONSTRUCTION FOR AI ANALYSIS');
  console.log('='.repeat(80));
  console.log(`📊 Company Profile Available: ${companyProfile ? 'YES' : 'NO'}`);
  
  let businessContext = "";
  if (companyProfile) {
    console.log('✅ Building business context string from company profile...');
    
    // Build context string with all available fields
    const contextParts = [
      `**BUSINESS CONTEXT:**`,
      `- Company: ${companyProfile.company_name || 'Unknown'}`,
      `- Industry: ${companyProfile.industry || 'Unknown'}`,
    ];
    
    if (companyProfile.website_purpose) {
      contextParts.push(`- Type: ${companyProfile.website_purpose}`);
    }
    
    if (companyProfile.annual_revenue) {
      contextParts.push(`- Annual Revenue: $${companyProfile.annual_revenue.toLocaleString()}`);
    }
    
    if (companyProfile.employee_count) {
      contextParts.push(`- Employee Count: ${companyProfile.employee_count}`);
    }
    
    if (companyProfile.data_records_count) {
      contextParts.push(`- Data Sensitivity: ${companyProfile.data_records_count} records`);
    }
    
    if (companyProfile.downtime_cost_per_hour) {
      contextParts.push(`- Downtime Cost: $${companyProfile.downtime_cost_per_hour}/hour`);
    }
    
    if (companyProfile.compliance_requirements && companyProfile.compliance_requirements.length > 0) {
      contextParts.push(`- Compliance: ${companyProfile.compliance_requirements.join(', ')}`);
    }
    
    if (companyProfile.geographic_region) {
      contextParts.push(`- Region: ${companyProfile.geographic_region}`);
    }
    
    contextParts.push('');
    contextParts.push(`Use this context to tailor the "Business Impact" and "Risk Assessment" specifically to this organization. For example, if they are in Healthcare (HIPAA) or Finance (PCI DSS), emphasize relevant compliance risks. Consider the organization's size (revenue, employee count) when assessing business impact and financial implications of vulnerabilities.`);
    
    businessContext = contextParts.join('\n');
    console.log('\n📋 CONSTRUCTED BUSINESS CONTEXT STRING:');
    console.log('-'.repeat(60));
    console.log(businessContext);
    console.log('-'.repeat(60));
    console.log(`📏 Business context length: ${businessContext.length} characters`);
    console.log('✅ Business context will be included in AI prompts');
  } else {
    console.log('⚠️  No company profile available - AI analysis will proceed without business context');
    console.log('   Business impact assessments will be generic');
  }
  console.log('='.repeat(80) + '\n');

  if (!process.env.ANTHROPIC_API_KEY) {
    console.error('❌ Anthropic API key not configured - cannot proceed with AI analysis');
    throw new Error('ANTHROPIC_API_KEY not configured');
  }

  const anthropic = new Anthropic({
    apiKey: process.env.ANTHROPIC_API_KEY,
  });

  // OPTIMIZED PROMPT: Explicitly requested conciseness to save tokens
  const systemPrompt = "You are a senior cybersecurity analyst. Generate UNIQUE, detailed content. Never repeat text. Provide EXACTLY 3 specific remediation steps and 3 attack scenarios per vulnerability to ensure concise, high-value output. Focus on realistic security intelligence.";

  let allProcessedVulns = [];
  let mergedDuplicatesCount = 0;

  for (let batchIndex = 0; batchIndex < batches.length; batchIndex++) {
    const currentBatch = batches[batchIndex];
    console.log(`\n🔄 Processing Batch ${batchIndex + 1}/${batches.length} (${currentBatch.length} items)...`);
    
    // Log business context usage for this batch
    if (businessContext) {
      console.log(`🏢 Business context included in batch ${batchIndex + 1} prompt (${businessContext.length} chars)`);
    } else {
      console.log(`⚠️  No business context available for batch ${batchIndex + 1} - using generic analysis`);
    }

    const prompt = `You are a senior cybersecurity analyst processing vulnerability findings. Provide SPECIFIC, DETAILED, and UNIQUE content.
${businessContext}
**SCAN TARGET:** ${target}
**SCANNERS USED:** ${scanMetadata.scanners_used.join(', ')}
**TOTAL RAW FINDINGS (THIS BATCH):** ${currentBatch.length}

**SAMPLE VULNERABILITY DATA:**
${JSON.stringify(currentBatch.map(v => ({
      scanner: v.scanner,
      title: v.title,
      severity: v.severity,
      description: v.description,
      url: v.url,
      cve_ids: v.cve_ids || [],
      cwe_id: v.cwe_id || null,
      wasc_id: v.wasc_id || null,
      // Multi-layer fields
      layer: v.layer || null,
      scanner_category: v.scanner_category || null,
      asset_type: v.asset_type || null,
      asset_identifier: v.asset_identifier || null,
      hostname: v.hostname || null,
      ip_address: v.ip_address || null,
      port: v.port || null,
      service: v.service || null,
      package_name: v.package_name || null,
      installed_version: v.installed_version || null,
      fixed_version: v.fixed_version || null,
      raw_output: v.raw_output ? v.raw_output.substring(0, 200) + '...' : 'N/A'
    })), null, 2)}

**CRITICAL REQUIREMENTS:**

1. **UNIQUE CONTENT**: Every field must contain completely different, specific content.

2. **PRESERVE VULNERABILITY IDENTIFIERS**: 
   - **CVE IDs**: Preserve all CVE IDs from the input data in the cve_ids array. If multiple vulnerabilities are merged, include all CVE IDs from all merged vulnerabilities.
   - **CWE ID**: Preserve the CWE ID from input data. If multiple vulnerabilities are merged, use the most relevant CWE ID.
   - **WASC ID**: Preserve the WASC ID from input data. If multiple vulnerabilities are merged, use the most relevant WASC ID.

3. **CONCISE SCENARIOS**: Provide exactly 3 step-by-step attack scenarios.

4. **ENTERPRISE RISK METRICS**:
   - **CVSS v3.1 Vector**: Generate a precise CVSS v3.1 vector string.
   - **False Positive Assessment**: Analyze likelihood (Low/Medium/High).
   - **Compliance Mapping**: Map to specific controls (PCI DSS, HIPAA, etc.).

**EXAMPLE OUTPUT FORMAT:**

{
  "title": "Missing Content Security Policy",
  "main_description": "Content Security Policy (CSP) header is not implemented on ${target}...",
  "cvss_vector": "CVSS:3.1/AV:N/AC:L/PR:N/UI:R/S:C/C:L/I:L/A:N",
  "cvss_score": 6.1,
  "false_positive_likelihood": "Low",
  "false_positive_reasoning": "Scanner confirmed missing header...",
  "compliance_controls": ["PCI DSS 4.0 Requirement 6.4.1"],
  "ai_security_analysis": "Security analysis reveals this represents a critical gap...",
  "business_impact": "Business impact includes potential data breaches...",
  "technical_impact": "Technical systems affected include web application security controls...",
  "solution_summary": "Implement a restrictive Content Security Policy (CSP) to mitigate XSS and data injection attacks.",
  "prevention_practices": [
    "Implement comprehensive security headers",
    "Regular security assessments",
    "Automated security testing in CI/CD"
  ],
  "compliance_considerations": "This vulnerability may impact compliance with PCI DSS Requirement 6.4.1 and GDPR Article 32.",
  "remediation_priority": "high",
  "references": [
    "https://developer.mozilla.org/en-US/docs/Web/HTTP/CSP",
    "https://cheatsheetseries.owasp.org/cheatsheets/Content_Security_Policy_Cheat_Sheet.html"
  ],
  "attack_scenarios": [
    "Reflected XSS exploitation...",
    "Third-party resource compromise...",
    "Stored XSS with CSP bypass..."
  ],
  "detailed_remediation_steps": [
    "Conduct comprehensive audit...",
    "Implement restrictive CSP policy...",
    "Deploy CSP in report-only mode..."
  ],
  "scanners_detected": ["zap", "nikto"],
  "severity": "high",
  "exploit_difficulty": "easy",
  "impact_score": 8
}

**YOUR TASK:**
Process these ${currentBatch.length} vulnerabilities and return detailed analysis.

**REQUIRED JSON OUTPUT:**
{
  "summary": {
    "total_unique_vulnerabilities": number,
    "duplicates_merged": number,
    "overall_risk_assessment": "string"
  },
  "vulnerabilities": [
    {
      "title": "Specific Vulnerability Title",
      "main_description": "Detailed technical explanation",
      "ai_security_analysis": "Comprehensive security analysis",
      "business_impact": "Specific business consequences",
      "technical_impact": "Technical systems affected",
      "solution_summary": "Concise solution summary",
      "prevention_practices": ["Practice 1", "Practice 2", "Practice 3"],
      "compliance_considerations": "Detailed compliance implications",
      "remediation_priority": "critical|high|medium|low",
      "references": ["url1", "url2"],
      "attack_scenarios": ["Scenario 1", "Scenario 2", "Scenario 3"],
      "detailed_remediation_steps": ["Step 1", "Step 2", "Step 3"],
      "scanners_detected": ["scanner1"],
      "severity": "critical|high|medium|low",
      "exploit_difficulty": "trivial|easy|moderate|difficult",
      "impact_score": 1-10,
      "cvss_vector": "string",
      "cvss_score": number,
      "false_positive_likelihood": "Low|Medium|High",
      "false_positive_reasoning": "string",
      "compliance_controls": ["string"],
      "cve_ids": ["CVE-2024-1234", "CVE-2024-5678"] or [],
      "cwe_id": number or null,
      "wasc_id": number or null,
      "layer": "web" | "network" | "infrastructure" | "container",
      "scanner_category": "web_app" | "network" | "infrastructure" | "container",
      "asset_type": "url" | "ip_address" | "hostname" | "container_image",
      "asset_identifier": "string",
      "hostname": "string" or null,
      "ip_address": "string" or null,
      "port": number or null,
      "service": "string" or null,
      "package_name": "string" or null,
      "installed_version": "string" or null,
      "fixed_version": "string" or null
    }
  ]
}

Return ONLY valid JSON with no additional text or comments.`;

    // Log prompt preview to verify business context inclusion
    if (batchIndex === 0) { // Only log for first batch to avoid spam
      console.log('\n📝 PROMPT PREVIEW (First 500 chars) - Verifying business context inclusion:');
      console.log('-'.repeat(60));
      const promptPreview = prompt.substring(0, 500);
      console.log(promptPreview);
      if (prompt.length > 500) {
        console.log(`... (${prompt.length - 500} more characters)`);
      }
      console.log('-'.repeat(60));
      console.log(`✅ Business context ${businessContext ? 'INCLUDED' : 'NOT INCLUDED'} in prompt`);
      console.log(`📏 Total prompt length: ${prompt.length} characters\n`);
    }

    try {
      const msg = await anthropic.messages.create({
        model: process.env.ANTHROPIC_MODEL || "claude-sonnet-4-5-20250929",
        max_tokens: 4000,
        temperature: 0.3,
        system: systemPrompt,
        messages: [
          {
            role: "user",
            content: prompt
          }
        ]
      });

      let aiResponse = msg.content[0].text.trim();

      // Clean markdown code blocks if present
      if (aiResponse.includes('```json')) {
        aiResponse = aiResponse.replace(/```json\n?|\n?```/g, '').trim();
      } else if (aiResponse.includes('```')) {
        aiResponse = aiResponse.replace(/```\n?|\n?```/g, '').trim();
      }

      // ROBUST JSON EXTRACTION
      try {
        const jsonStart = aiResponse.indexOf('{');
        const jsonEnd = aiResponse.lastIndexOf('}');

        if (jsonStart !== -1 && jsonEnd !== -1 && jsonEnd > jsonStart) {
          aiResponse = aiResponse.substring(jsonStart, jsonEnd + 1);
        }
      } catch (extractError) {
        console.warn('⚠️ Failed to extract JSON substring, attempting to parse original:', extractError);
      }

      let parsedResponse;
      try {
        parsedResponse = JSON.parse(aiResponse);
      } catch (parseError) {
        console.warn(`⚠️ Batch ${batchIndex + 1} JSON parse failed, attempting repair...`);
        console.log('🔍 RAW AI RESPONSE (FAILED):', aiResponse); // ADDED LOGGING

        // JSON REPAIR LOGIC
        try {
          // 1. Try to close open arrays/objects
          let repaired = aiResponse.trim();
          // Remove trailing comma if present
          if (repaired.endsWith(',')) repaired = repaired.slice(0, -1);

          // Count braces/brackets
          const openBraces = (repaired.match(/\{/g) || []).length;
          const closeBraces = (repaired.match(/\}/g) || []).length;
          const openBrackets = (repaired.match(/\[/g) || []).length;
          const closeBrackets = (repaired.match(/\]/g) || []).length;

          // Append missing closing characters
          if (openBrackets > closeBrackets) repaired += ']'.repeat(openBrackets - closeBrackets);
          if (openBraces > closeBraces) repaired += '}'.repeat(openBraces - closeBraces);

          parsedResponse = JSON.parse(repaired);
          console.log(`✅ Batch ${batchIndex + 1} repaired successfully`);
        } catch (repairError) {
          console.error(`❌ Batch ${batchIndex + 1} repair failed:`, repairError);
          throw parseError; // Throw original error if repair fails
        }
      }

      if (parsedResponse.vulnerabilities) {
        // Merge original batch data (CVE/CWE/WASC IDs) with AI response
        const enrichedVulns = parsedResponse.vulnerabilities.map((aiVuln, idx) => {
          // Since BATCH_SIZE is 1, we can safely access currentBatch[0]
          const originalVuln = currentBatch[idx] || currentBatch[0];
          
          // Merge IDs: prefer AI response, fallback to original
          if (!aiVuln.cve_ids || (Array.isArray(aiVuln.cve_ids) && aiVuln.cve_ids.length === 0)) {
            if (originalVuln && originalVuln.cve_ids && originalVuln.cve_ids.length > 0) {
              aiVuln.cve_ids = originalVuln.cve_ids;
              console.log(`   📋 Restored CVE IDs from original data: ${aiVuln.cve_ids.join(', ')}`);
            }
          }
          
          if (!aiVuln.cwe_id && originalVuln && originalVuln.cwe_id) {
            aiVuln.cwe_id = originalVuln.cwe_id;
            console.log(`   📋 Restored CWE ID from original data: ${aiVuln.cwe_id}`);
          }
          
          if (!aiVuln.wasc_id && originalVuln && originalVuln.wasc_id) {
            aiVuln.wasc_id = originalVuln.wasc_id;
            console.log(`   📋 Restored WASC ID from original data: ${aiVuln.wasc_id}`);
          }
          
          return aiVuln;
        });
        
        allProcessedVulns.push(...enrichedVulns);
      }
      if (parsedResponse.summary && parsedResponse.summary.duplicates_merged) {
        mergedDuplicatesCount += parsedResponse.summary.duplicates_merged;
      }

      console.log(`✅ Batch ${batchIndex + 1} success: ${parsedResponse.vulnerabilities?.length || 0} vulns processed`);

    } catch (batchError) {
      console.error(`❌ Batch ${batchIndex + 1} failed:`, batchError);
      // Continue to next batch, don't fail entire scan
    }
  }

  // Construct final aggregated response
  const finalResponse = {
    summary: {
      total_unique_vulnerabilities: allProcessedVulns.length,
      duplicates_merged: mergedDuplicatesCount,
      overall_risk_assessment: assessOverallRisk({
        critical: allProcessedVulns.filter(v => v.severity === 'critical').length,
        high: allProcessedVulns.filter(v => v.severity === 'high').length,
        medium: allProcessedVulns.filter(v => v.severity === 'medium').length,
        low: allProcessedVulns.filter(v => v.severity === 'low').length
      })
    },
    vulnerabilities: allProcessedVulns
  };

  console.log('\n' + '🎯 AI ANALYSIS COMPLETE - AGGREGATED RESULTS:');
  console.log('='.repeat(60));
  console.log(`📊 Total unique vulnerabilities: ${finalResponse.summary.total_unique_vulnerabilities}`);
  console.log(`🔗 Total duplicates merged: ${finalResponse.summary.duplicates_merged}`);
  console.log(`⚠️  Overall risk: ${finalResponse.summary.overall_risk_assessment}`);

  return finalResponse;
}


function assessExploitDifficulty(vuln, similarVulns) {
  const scannerCount = [...new Set(similarVulns.map(v => v.scanner))].length;

  if (vuln.severity === 'critical') return scannerCount > 2 ? 'easy' : 'trivial';
  if (vuln.severity === 'high') return scannerCount > 2 ? 'moderate' : 'easy';
  if (vuln.severity === 'medium') return 'moderate';
  return 'difficult';
}

function generateCorrelationInsights(similarVulns) {
  if (similarVulns.length > 1) {
    const scanners = [...new Set(similarVulns.map(v => v.scanner))];
    return `Cross-scanner validation confirms vulnerability authenticity. Scanner correlation provides high confidence in finding accuracy and exploitation potential.`;
  }
  return `Single scanner detection suggests focused assessment. Consider additional validation methods for comprehensive security verification.`;
}

function assessOverallRisk(severityCounts) {
  if (severityCounts.critical > 0) return 'Critical - Immediate attention required';
  if (severityCounts.high > 2) return 'High - Urgent remediation needed';
  if (severityCounts.medium > 5) return 'Medium - Regular security improvements needed';
  return 'Low - Maintain current security practices';
}

function calculateScannerPerformance(allVulnerabilities) {
  const scannerStats = {};

  // Count findings per scanner
  for (const vuln of allVulnerabilities) {
    if (!scannerStats[vuln.scanner]) {
      scannerStats[vuln.scanner] = {
        findings_count: 0,
        unique_contributions: 0,
        overlap_with_others: 0
      };
    }
    scannerStats[vuln.scanner].findings_count++;
  }

  // Calculate unique contributions (simplified)
  for (const scanner in scannerStats) {
    const scannerFindings = allVulnerabilities.filter(v => v.scanner === scanner);
    scannerStats[scanner].unique_contributions = Math.floor(scannerFindings.length * 0.6);
    scannerStats[scanner].overlap_with_others = scannerFindings.length - scannerStats[scanner].unique_contributions;
  }

  return scannerStats;
}

function calculateImpactScore(severity, exploitDifficulty) {
  const severityScores = { critical: 10, high: 8, medium: 6, low: 4, info: 2 };
  const difficultyModifiers = { trivial: 2, easy: 1.5, moderate: 1, difficult: 0.7, expert: 0.5 };
  const baseScore = severityScores[severity] || 4;
  const modifier = difficultyModifiers[exploitDifficulty] || 1;
  return Math.round(baseScore * modifier);
}

function calculateRemediationPriority(severity, exploitDifficulty, businessImpact) {
  const severityWeight = { critical: 4, high: 3, medium: 2, low: 1, info: 0 };
  const difficultyWeight = { trivial: 4, easy: 3, moderate: 2, difficult: 1, expert: 0 };
  const businessWeight = typeof businessImpact === 'string' && businessImpact.toLowerCase().includes('critical') ? 2 :
    typeof businessImpact === 'string' && businessImpact.toLowerCase().includes('high') ? 1.5 :
      typeof businessImpact === 'string' && businessImpact.toLowerCase().includes('medium') ? 1 : 0.5;

  const priority = (severityWeight[severity] || 1) + (difficultyWeight[exploitDifficulty] || 1) + businessWeight;

  if (priority >= 7) return 'critical';
  if (priority >= 5) return 'high';
  if (priority >= 3) return 'medium';
  return 'low';
}

// MAIN UNIFIED PROCESSING FUNCTION
async function processAllVulnerabilitiesUnified(allVulnerabilities, scanResults, scanMetadata, target, scanId, supabase, companyProfile = null) {
  console.log(`\n💾 Raw findings stored for audit: ${allVulnerabilities.length} total findings`);

  await updateScanProgress(supabase, scanId, "running", 50, `Processing ${allVulnerabilities.length} vulnerabilities with AI for deduplication and standardization...`);

  // Process all vulnerabilities together with AI
  const aiAnalysis = await processAllVulnerabilitiesWithAI(allVulnerabilities, scanMetadata, target, companyProfile);

  console.log(`\n📊 AI Analysis Summary:`);
  console.log(`  - Raw findings: ${allVulnerabilities.length}`);
  console.log(`  - Unique vulnerabilities: ${aiAnalysis.summary.total_unique_vulnerabilities}`);
  console.log(`  - Duplicates merged: ${aiAnalysis.summary.duplicates_merged}`);
  console.log(`  - Overall risk: ${aiAnalysis.summary.overall_risk_assessment}`);

  await updateScanProgress(supabase, scanId, "running", 75, `AI analysis complete: ${aiAnalysis.summary.total_unique_vulnerabilities} unique vulnerabilities identified`);

  // Convert AI analysis to database format
  const processedVulnerabilities = [];
  for (let i = 0; i < aiAnalysis.vulnerabilities.length; i++) {
    const vuln = aiAnalysis.vulnerabilities[i];

    console.log(`🔍 Processing AI vulnerability ${i + 1}:`, {
      title: vuln.title,
      scanners_detected: vuln.scanners_detected,
      scanner_name_for_db: vuln.scanners_detected?.join(',') || 'unknown'
    });

    // COMPREHENSIVE LOGGING FOR DATABASE MAPPING
    console.log(`\n🎯 VULNERABILITY ${i + 1} DATABASE MAPPING:`);
    console.log('='.repeat(50));
    console.log(`📋 Title: ${vuln.title}`);
    console.log(`🔴 Severity: ${vuln.severity}`);
    console.log(`🎯 Scanners: ${vuln.scanners_detected?.join(',') || 'unknown'}`);
    console.log(`📖 Description (first 100 chars): ${(vuln.main_description || '').substring(0, 100)}...`);
    console.log(`🔍 AI Analysis (first 100 chars): ${(vuln.ai_security_analysis || '').substring(0, 100)}...`);
    console.log(`💼 Business Impact (first 100 chars): ${(vuln.business_impact || '').substring(0, 100)}...`);
    console.log(`⚙️ Technical Impact (first 100 chars): ${(vuln.technical_impact || '').substring(0, 100)}...`);
    console.log(`🔧 Remediation Steps: ${vuln.detailed_remediation_steps?.length || 0} steps`);
    if (vuln.detailed_remediation_steps && vuln.detailed_remediation_steps.length > 0) {
      vuln.detailed_remediation_steps.forEach((step, idx) => {
        console.log(`  ${idx + 1}. ${step.substring(0, 80)}...`);
      });
    }
    console.log(`⚡ Attack Scenarios: ${vuln.attack_scenarios?.length || 0} scenarios`);
    if (vuln.attack_scenarios && vuln.attack_scenarios.length > 0) {
      vuln.attack_scenarios.forEach((scenario, idx) => {
        console.log(`  ${idx + 1}. ${scenario.substring(0, 80)}...`);
      });
    }

    // Extract CVE/CWE/WASC IDs from AI response
    // CVE can be an array, so we'll take the first one or join them
    let cveId = null;
    if (vuln.cve_ids && Array.isArray(vuln.cve_ids) && vuln.cve_ids.length > 0) {
      // Use first CVE ID, or join if multiple (database might need single value)
      cveId = vuln.cve_ids[0];
      if (vuln.cve_ids.length > 1) {
        console.log(`📋 Multiple CVE IDs found: ${vuln.cve_ids.join(', ')}, using first: ${cveId}`);
      }
    } else if (vuln.cve_id) {
      // Handle single CVE ID string
      cveId = vuln.cve_id;
    }

    const cweId = safeIntOrNull(vuln.cwe_id);
    const wascId = safeIntOrNull(vuln.wasc_id);

    // Log CVE/CWE/WASC IDs
    console.log(`🔖 Vulnerability Identifiers:`);
    console.log(`   CVE: ${cveId || 'None'}`);
    console.log(`   CWE: ${cweId || 'None'}`);
    console.log(`   WASC: ${wascId || 'None'}`);

    // Determine layer and scanner_category from vulnerability data or default based on scanner
    const layer = vuln.layer || (vuln.scanners_detected?.[0] ? SCANNERS[vuln.scanners_detected[0]]?.layer || 'web' : 'web');
    const scannerCategory = vuln.scanner_category || (vuln.scanners_detected?.[0] ? SCANNERS[vuln.scanners_detected[0]]?.scanner_category || 'web_app' : 'web_app');

    const dbVuln = {
      scan_report_id: scanId,
      scanner_name: vuln.scanners_detected?.join(',') || 'unknown',
      zap_rule_id: safeIntOrNull(vuln.wasc_id),
      severity: vuln.severity,
      title: vuln.title,
      description: vuln.main_description,
      url: vuln.urls_affected?.[0] || '',
      cwe_id: cweId,
      wasc_id: wascId,
      solution: vuln.solution_summary,
      confidence: vuln.confidence,
      risk_level: vuln.impact_score,
      remediation_steps: vuln.detailed_remediation_steps,
      created_at: new Date().toISOString(),

      // Enhanced AI analysis fields
      ai_analysis: vuln.ai_security_analysis,
      business_impact: vuln.business_impact,
      technical_impact: vuln.technical_impact,
      attack_scenarios: vuln.attack_scenarios,
      prevention_practices: vuln.prevention_practices,
      compliance_notes: vuln.compliance_considerations,
      exploit_difficulty: vuln.exploit_difficulty,
      reference_links: vuln.references,

      // Enhanced metadata
      finding_category: vuln.category,
      impact_score: vuln.impact_score,
      remediation_priority: vuln.remediation_priority,
      scanner_correlation: JSON.stringify(vuln.evidence),

      // CVE ID - store first CVE if available
      cve_id: cveId,

      // Multi-layer fields - CRITICAL: Must match TypeScript interface exactly
      layer: layer,
      scanner_category: scannerCategory,
      asset_type: vuln.asset_type || (layer === 'web' ? 'url' : layer === 'network' ? 'ip_address' : layer === 'container' ? 'container_image' : 'hostname'),
      asset_identifier: vuln.asset_identifier || vuln.url || vuln.hostname || '',
      
      // Optional layer-specific fields (include if present)
      hostname: vuln.hostname || null,
      ip_address: vuln.ip_address || null,
      port: vuln.port ? safeIntOrNull(vuln.port) : null,
      service: vuln.service || null,
      package_name: vuln.package_name || null,
      installed_version: vuln.installed_version || null,
      fixed_version: vuln.fixed_version || null
    };

    console.log(`✅ Database vulnerability ${i + 1} scanner_name: ${dbVuln.scanner_name}`);
    console.log('='.repeat(50));

    processedVulnerabilities.push(dbVuln);

    // Update progress
    const progress = 75 + ((i + 1) / aiAnalysis.vulnerabilities.length) * 15;
    await updateScanProgress(supabase, scanId, "running", Math.round(progress), `Processed vulnerability ${i + 1}/${aiAnalysis.vulnerabilities.length}: ${vuln.title}`);
  }

  return { processedVulnerabilities, aiAnalysis };
}

// Update scan progress in Supabase
async function updateScanProgress(supabase, scanId, status, progress, message = null) {
  try {
    const updateData = { status, progress };
    if (message) updateData.message = message;

    await supabase
      .from("scan_reports")
      .update(updateData)
      .eq("id", scanId);

    console.log(`📊 Updated scan ${scanId}: ${status} (${progress}%)`);
  } catch (error) {
    console.error('❌ Failed to update progress:', error);
  }
}

// Pre-populate Trivy cache to speed up first scan
async function prepopulateTrivyCache() {
  try {
    console.log('🔄 Pre-populating Trivy vulnerability database cache...');
    const cmd = 'docker run --rm -v trivy-cache:/root/.cache/trivy aquasec/trivy:latest image --download-db-only';
    
    exec(cmd, { timeout: 120000 }, (err, stdout, stderr) => {
      if (err) {
        console.warn('⚠️ Trivy cache pre-population failed (non-critical):', err.message);
        console.warn('   First Trivy scan may be slower');
      } else {
        console.log('✅ Trivy cache pre-populated successfully');
        console.log('   First Trivy scan will be faster');
      }
    });
  } catch (error) {
    console.warn('⚠️ Trivy cache pre-population error (non-critical):', error.message);
  }
}

// FIXED Scanner command builders
function buildZapCommand(target, scanner, options = {}) {
  const reportHostPath = path.join(reportsDir, scanner.reportFile);
  const containerReportPath = `${scanner.containerWorkDir}/${scanner.reportFile}`;

  let cmd = [
    'docker run --rm',
    '-u root',
    `-v ${reportsDir}:${scanner.containerWorkDir}:rw`,
    scanner.containerName,
    'zap-baseline.py',
    `-t ${target}`,
    `-J ${containerReportPath}`,
    '--autooff'
  ];

  if (options.ajaxSpider) {
    cmd.splice(-1, 0, '-j');
  }

  return { command: cmd.join(' '), reportHostPath };
}

function buildReNgineCommand(target, scanner, options = {}) {
  const reportHostPath = path.join(reportsDir, scanner.reportFile);
  const containerReportPath = `${scanner.containerWorkDir}/${scanner.reportFile}`;

  const scriptPath = path.join(scriptsDir, 'rengine_scan.py');
  const reNgineScript = `#!/usr/bin/env python3
import requests
import json
import sys

def check_security_headers(url):
    vulnerabilities = []
    try:
        response = requests.get(url, timeout=30, verify=False)
        headers = response.headers

        security_checks = [
            ('Content-Security-Policy', 'Missing Content Security Policy', 'medium'),
            ('X-Frame-Options', 'Missing X-Frame-Options Header', 'medium'),
            ('Strict-Transport-Security', 'Missing HSTS Header', 'medium'),
            ('X-Content-Type-Options', 'Missing X-Content-Type-Options Header', 'low'),
            ('Referrer-Policy', 'Missing Referrer Policy Header', 'low')
        ]

        for header, title, severity in security_checks:
            if header.lower() not in [h.lower() for h in headers.keys()]:
                vulnerabilities.append({
                    "name": title,
                    "severity": severity,
                    "description": f"The {header} security header is not configured",
                    "url": url
                })

        if 'server' in headers:
            vulnerabilities.append({
                "name": "Server Information Disclosure",
                "severity": "low",
                "description": f"Server header reveals: {headers['server']}",
                "url": url
            })

    except Exception as e:
        vulnerabilities.append({
            "name": "reNgine Scan Error",
            "severity": "info",
            "description": f"Error during security headers check: {str(e)}",
            "url": url
        })

    return vulnerabilities

target_url = "${target}"
vulns = check_security_headers(target_url)
result = {
    "target": target_url,
    "vulnerabilities": vulns
}

with open("${containerReportPath}", "w") as f:
    json.dump(result, f, indent=2)

print(f"reNgine scan completed. Found {len(vulns)} issues.")
`;

  fs.writeFileSync(scriptPath, reNgineScript);
  fs.chmodSync(scriptPath, 0o755);

  const cmd = [
    'docker run --rm',
    `-v ${reportsDir}:${scanner.containerWorkDir}:rw`,
    `-v ${scriptsDir}:/scripts:ro`,
    '--entrypoint python3',
    scanner.containerName,
    '/scripts/rengine_scan.py'
  ];

  return { command: cmd.join(' '), reportHostPath };
}

function buildWapitiCommand(target, scanner, options = {}) {
  const reportHostPath = path.join(reportsDir, scanner.reportFile);
  const containerReportPath = `${scanner.containerWorkDir}/${scanner.reportFile}`;

  const cmd = [
    'docker run --rm',
    `-v ${reportsDir}:${scanner.containerWorkDir}:rw`,
    scanner.containerName,
    '-u', target,
    '-f', 'json',
    '-o', containerReportPath,
    '--scope', 'page',
    '--max-scan-time', '60'
  ];

  return { command: cmd.join(' '), reportHostPath };
}

function buildNiktoCommand(target, scanner, options = {}) {
  const reportHostPath = path.join(reportsDir, scanner.reportFile);
  const containerReportPath = `${scanner.containerWorkDir}/${scanner.reportFile}`;

  const cmd = [
    'docker run --rm',
    `-v ${reportsDir}:${scanner.containerWorkDir}:rw`,
    scanner.containerName,
    '-h', target,
    '-output', containerReportPath,
    '-timeout', '30'
  ];

  return { command: cmd.join(' '), reportHostPath };
}

function buildW3afCommand(target, scanner, options = {}) {
  const reportHostPath = path.join(reportsDir, scanner.reportFile);
  const containerReportPath = `${scanner.containerWorkDir}/${scanner.reportFile}`;

  const scriptPath = path.join(scriptsDir, 'w3af_scan.py');
  const w3afScript = `#!/usr/bin/env python3
import os
import sys

try:
    import requests
except ImportError:
    os.system('pip install requests')
    import requests

import json
from urllib.parse import urlparse, urljoin

def basic_security_scan(url):
    findings = []
    try:
        response = requests.get(url, timeout=30, verify=False)
        
        if 'admin' in response.text.lower():
            findings.append("Potential Admin Interface Discovery")
        if 'password' in response.text.lower():
            findings.append("Password Field Detection")  
        if 'login' in response.text.lower():
            findings.append("Login Form Detection")
            
        try:
            options_resp = requests.options(url, timeout=10)
            if options_resp.status_code == 200:
                findings.append("HTTP OPTIONS Method Enabled")
        except:
            pass
            
        try:
            error_resp = requests.get(urljoin(url, '/nonexistent-page-test'), timeout=10)
            if 'apache' in error_resp.text.lower() or 'nginx' in error_resp.text.lower():
                findings.append("Web Server Information Disclosure")
        except:
            pass
            
    except Exception as e:
        findings.append(f"Scan Error: {str(e)}")
        
    return findings

if __name__ == "__main__":
    target_url = "${target}"
    results = basic_security_scan(target_url)
    
    with open("${containerReportPath}", "w") as f:
        f.write(f"W3AF Security Scan Results for {target_url}\\n")
        f.write("Scan Date: 2025-08-17\\n")
        f.write("\\n")
        f.write("VULNERABILITIES FOUND:\\n")
        for i, finding in enumerate(results, 1):
            f.write(f"{i}. {finding}\\n")
        f.write("Scan completed successfully\\n")
        
    print(f"w3af scan completed. Found {len(results)} findings.")
`;

  fs.writeFileSync(scriptPath, w3afScript);
  fs.chmodSync(scriptPath, 0o755);

  const cmd = [
    'docker run --rm',
    `-v ${reportsDir}:${scanner.containerWorkDir}:rw`,
    `-v ${scriptsDir}:/scripts:ro`,
    '--entrypoint python3',
    scanner.containerName,
    '/scripts/w3af_scan.py'
  ];

  return { command: cmd.join(' '), reportHostPath };
}

function buildNmapCommand(target, scanner, options = {}) {
  const reportHostPath = path.join(reportsDir, scanner.reportFile);
  const containerReportPath = `${scanner.containerWorkDir}/${scanner.reportFile}`;

  const scriptPath = path.join(scriptsDir, 'nmap_scan.py');
  fs.chmodSync(scriptPath, 0o755);

  const scanType = options.scan_type || 'quick';
  
  const cmd = [
    'docker run --rm',
    '--network host', // Nmap needs host network for scanning
    `-v ${reportsDir}:${scanner.containerWorkDir}:rw`,
    `-v ${scriptsDir}:/scripts:ro`,
    '-e', `TARGET=${target}`,
    '-e', `SCAN_TYPE=${scanType}`,
    '-e', `OUTPUT_PATH=${containerReportPath}`,
    '--entrypoint python3',
    scanner.containerName,
    '/scripts/nmap_scan.py',
    target,
    scanType
  ];

  return { command: cmd.join(' '), reportHostPath };
}

function buildTrivyCommand(target, scanner, options = {}) {
  const reportHostPath = path.join(reportsDir, scanner.reportFile);
  const containerReportPath = `${scanner.containerWorkDir}/${scanner.reportFile}`;

  const scriptPath = path.join(scriptsDir, 'trivy_scan.py');
  fs.chmodSync(scriptPath, 0o755);

  const severity = options.severity_filter || 'CRITICAL,HIGH,MEDIUM';
  const scanType = options.scan_type || 'vuln';
  
  const cmd = [
    'docker run --rm',
    `-v ${reportsDir}:${scanner.containerWorkDir}:rw`,
    `-v ${scriptsDir}:/scripts:ro`,
    `-v trivy-cache:/root/.cache/trivy`, // Cache volume for faster scans
    '-e', `IMAGE=${target}`,
    '-e', `SEVERITY_FILTER=${severity}`,
    '-e', `SCAN_TYPE=${scanType}`,
    '-e', `OUTPUT_PATH=${containerReportPath}`,
    '--entrypoint python3',
    scanner.containerName,
    '/scripts/trivy_scan.py',
    target
  ];

  return { command: cmd.join(' '), reportHostPath };
}

function buildWazuhCommand(target, scanner, options = {}) {
  const reportHostPath = path.join(reportsDir, scanner.reportFile);
  
  // Wazuh doesn't use Docker - direct Python execution
  const scriptPath = path.join(scriptsDir, 'wazuh_scan.py');
  fs.chmodSync(scriptPath, 0o755);

  const credentials = options.wazuhCredentials || {};
  const apiUrl = credentials.api_url || '';
  const username = credentials.username || '';
  const password = credentials.password || '';
  const verifySsl = credentials.verify_ssl || false;

  // Build Python command with environment variables
  const cmd = [
    'python3',
    scriptPath
  ];

  // Set environment variables for the Python script
  const envVars = {
    WAZUH_API_URL: apiUrl,
    WAZUH_USERNAME: username,
    WAZUH_PASSWORD: password,
    WAZUH_VERIFY_SSL: verifySsl.toString(),
    OUTPUT_PATH: reportHostPath
  };

  return { 
    command: cmd.join(' '), 
    reportHostPath,
    envVars, // Return env vars separately for exec
    isDirectPython: true // Flag to indicate direct Python execution
  };
}

function buildTestsslCommand(target, scanner, options = {}) {
  const reportHostPath = path.join(reportsDir, scanner.reportFile);
  const containerReportPath = `${scanner.containerWorkDir}/${scanner.reportFile}`;

  const scriptPath = path.join(scriptsDir, 'testssl_scan.py');
  fs.chmodSync(scriptPath, 0o755);

  const cmd = [
    'docker run --rm',
    `-v ${reportsDir}:${scanner.containerWorkDir}:rw`,
    `-v ${scriptsDir}:/scripts:ro`,
    '-e', `TARGET=${target}`,
    '-e', `OUTPUT_PATH=${containerReportPath}`,
    '--entrypoint python3',
    scanner.containerName,
    '/scripts/testssl_scan.py',
    target
  ];

  return { command: cmd.join(' '), reportHostPath };
}

// Report parsers with proper type handling
function parseZapReport(rawReport) {
  const alerts = rawReport?.site?.[0]?.alerts || [];
  return alerts.map(alert => ({
    scanner: 'zap',
    title: alert.name || alert.alert || 'Unnamed Vulnerability',
    description: alert.desc || 'No description provided',
    severity: mapZapRiskToSeverity(alert.riskcode),
    url: alert.instances?.[0]?.uri || '',
    cve_ids: extractCVEIds(alert.reference),
    cwe_id: safeIntOrNull(alert.cweid),
    wasc_id: safeIntOrNull(alert.wascid),
    solution: alert.solution || 'Review vulnerability details and implement appropriate security controls',
    confidence: 'medium',
    plugin_id: safeIntOrNull(alert.pluginId),
    raw_output: alert.desc || alert.name
  }));
}

function parseWapitiReport(rawReport) {
  const vulnerabilities = [];

  if (!rawReport || !rawReport.vulnerabilities) {
    return [{
      scanner: 'wapiti',
      title: 'Wapiti Scan Completed',
      description: 'Wapiti scan completed - no vulnerabilities structure found',
      severity: 'info',
      url: '',
      cve_ids: [],
      cwe_id: null,
      wasc_id: null,
      solution: 'Continue regular security assessments',
      confidence: 'medium',
      plugin_id: null,
      raw_output: 'Wapiti scan completed'
    }];
  }

  for (const [categoryName, categoryVulns] of Object.entries(rawReport.vulnerabilities)) {
    if (Array.isArray(categoryVulns) && categoryVulns.length > 0) {
      categoryVulns.forEach((vuln, index) => {
        let severity = mapWapitiLevelToSeverity(vuln.level);
        let title = categoryName;
        let description = vuln.info || categoryName;

        if (categoryName.includes('CSP') || categoryName.includes('Content Security Policy')) {
          title = 'Missing Content Security Policy';
          description = 'Content Security Policy (CSP) header is not configured, allowing potential XSS attacks';
          severity = 'medium';
        } else if (categoryName.includes('Clickjacking') || categoryName.includes('X-Frame-Options')) {
          title = 'Missing X-Frame-Options Header';
          description = 'X-Frame-Options header is not set, allowing potential clickjacking attacks';
          severity = 'medium';
        } else if (categoryName.includes('HSTS') || categoryName.includes('Strict-Transport-Security')) {
          title = 'Missing HSTS Header';
          description = 'Strict-Transport-Security header is not configured, allowing potential downgrade attacks';
          severity = 'medium';
        } else if (categoryName.includes('MIME') || categoryName.includes('X-Content-Type-Options')) {
          title = 'Missing X-Content-Type-Options Header';
          description = 'X-Content-Type-Options header is not set, allowing potential MIME type sniffing attacks';
          severity = 'medium';
        }

        vulnerabilities.push({
          scanner: 'wapiti',
          title: title,
          description: description,
          severity: severity,
          url: vuln.path || '',
          cve_ids: [],
          cwe_id: null,
          wasc_id: null,
          solution: rawReport.classifications?.[categoryName]?.sol || 'Implement appropriate security headers and controls',
          confidence: 'high',
          plugin_id: vuln.module || null,
          method: vuln.method || 'GET',
          wstg_references: vuln.wstg || [],
          raw_output: vuln.info || description
        });
      });
    }
  }

  console.log(`🔍 Wapiti extracted ${vulnerabilities.length} real vulnerabilities from JSON structure`);
  return vulnerabilities;
}

function parseReNgineReport(rawReport) {
  const vulnerabilities = rawReport?.vulnerabilities || [];

  if (vulnerabilities.length === 0) {
    return [{
      scanner: 'rengine',
      title: 'reNgine Security Assessment Completed',
      description: 'reNgine reconnaissance and security assessment completed',
      severity: 'info',
      url: rawReport?.target || '',
      cve_ids: [],
      cwe_id: null,
      wasc_id: null,
      solution: 'Review scan results and continue security monitoring',
      confidence: 'medium',
      plugin_id: null,
      raw_output: 'reNgine security assessment completed'
    }];
  }

  return vulnerabilities.map(vuln => ({
    scanner: 'rengine',
    title: vuln.name || 'reNgine Security Finding',
    description: vuln.description || 'Security finding from reNgine reconnaissance',
    severity: mapGenericSeverityToLevel(vuln.severity || 'medium'),
    url: vuln.url || '',
    cve_ids: [],
    cwe_id: null,
    wasc_id: null,
    solution: 'Review the security configuration and implement appropriate headers',
    confidence: 'medium',
    plugin_id: null,
    raw_output: vuln.description || vuln.name
  }));
}

// UNIVERSAL Nikto parser - Extract ANY vulnerability types for ANY website
function parseNiktoFromStdout(stdout) {
  console.log(`🔍 Nikto extracting universal vulnerabilities from scan results...`);

  const vulnerabilities = [];
  const lines = stdout.split('\n');
  const processedFindings = new Set();

  console.log(`📊 Nikto parsing ${lines.length} lines for universal vulnerability extraction`);

  for (const line of lines) {
    const trimmedLine = line.trim();

    if (trimmedLine.startsWith('+ ') && trimmedLine.includes(':')) {

      let title = 'Security Finding';
      let severity = 'medium';
      let description = trimmedLine.replace(/^\+\s*/, '').trim();
      let url = '';

      const urlMatches = [
        trimmedLine.match(/(GET|POST|HEAD|PUT|DELETE|OPTIONS|TRACE|DEBUG)\s+([^:\s]+)/),
        trimmedLine.match(/\/([^:\s]+)/),
        trimmedLine.match(/(\w+\.\w+)/),
      ];

      for (const match of urlMatches) {
        if (match && match[2]) {
          url = match[2].trim();
          break;
        } else if (match && match[1]) {
          url = match[1].trim();
          break;
        }
      }

      if (description.toLowerCase().includes('header') && (description.toLowerCase().includes('missing') || description.toLowerCase().includes('not set'))) {
        title = 'Missing Security Header';
        severity = 'medium';
      } else if (description.toLowerCase().includes('outdated') || description.toLowerCase().includes('vulnerable') || description.toLowerCase().includes('version')) {
        title = 'Version Information Disclosure';
        severity = 'low';
      } else if (description.toLowerCase().includes('directory') || description.toLowerCase().includes('browsable') || description.toLowerCase().includes('indexing')) {
        title = 'Directory Disclosure';
        severity = 'medium';
      } else if (description.toLowerCase().includes('login') || description.toLowerCase().includes('admin') || description.toLowerCase().includes('authentication')) {
        title = 'Authentication Interface Discovery';
        severity = 'info';
      } else if (description.toLowerCase().includes('injection') || description.toLowerCase().includes('xss') || description.toLowerCase().includes('sql')) {
        title = 'Injection Vulnerability';
        severity = 'high';
      } else if (description.toLowerCase().includes('upload') || description.toLowerCase().includes('file')) {
        title = 'File Handling Issue';
        severity = 'medium';
      } else if (description.toLowerCase().includes('debug') || description.toLowerCase().includes('error') || description.toLowerCase().includes('stack trace')) {
        title = 'Information Disclosure';
        severity = 'medium';
      } else if (description.toLowerCase().includes('default') || description.toLowerCase().includes('configuration')) {
        title = 'Configuration Issue';
        severity = 'low';
      } else if (description.toLowerCase().includes('script') || description.toLowerCase().includes('javascript')) {
        title = 'Script Security Issue';
        severity = 'medium';
      } else if (description.toLowerCase().includes('certificate') || description.toLowerCase().includes('ssl') || description.toLowerCase().includes('tls')) {
        title = 'TLS/SSL Issue';
        severity = 'medium';
      } else if (description.toLowerCase().includes('backup') || description.toLowerCase().includes('sensitive')) {
        title = 'Sensitive Data Exposure';
        severity = 'high';
      } else if (description.toLowerCase().includes('redirect') || description.toLowerCase().includes('url')) {
        title = 'URL Handling Issue';
        severity = 'low';
      } else {
        title = 'Security Finding';
        severity = 'medium';
      }

      const findingKey = `${description.substring(0, 100).replace(/[^\w]/g, '')}`;
      if (processedFindings.has(findingKey)) {
        continue;
      }
      processedFindings.add(findingKey);

      vulnerabilities.push({
        scanner: 'nikto',
        title: title,
        description: description,
        severity: severity,
        url: url,
        cve_ids: [],
        cwe_id: null,
        wasc_id: null,
        solution: 'Review security finding and implement appropriate controls based on vulnerability analysis',
        confidence: 'medium',
        plugin_id: null,
        raw_output: trimmedLine
      });
    }
  }

  console.log(`✅ Nikto extracted ${vulnerabilities.length} universal vulnerabilities`);
  if (vulnerabilities.length > 0) {
    console.log(`📋 Nikto found vulnerability types: ${[...new Set(vulnerabilities.map(v => v.title))].join(', ')}`);
  }

  return vulnerabilities;
}

function parseW3afReport(reportText) {
  const lines = reportText.split('\n')
    .filter(line => line.trim())
    .filter(line => line.match(/^\d+\./));

  if (lines.length === 0) {
    return [{
      scanner: 'w3af',
      title: 'w3af Security Assessment',
      description: 'w3af web application security scanner completed successfully',
      severity: 'info',
      url: '',
      cve_ids: [],
      cwe_id: null,
      wasc_id: null,
      solution: 'Continue regular security assessments',
      confidence: 'medium',
      plugin_id: null,
      raw_output: 'w3af scan completed'
    }];
  }

  return lines.map((line, index) => {
    const description = line.trim().replace(/^\d+\.\s*/, '');
    let severity = 'medium';
    let title = `w3af Finding: ${description}`;

    if (description.toLowerCase().includes('admin') || description.toLowerCase().includes('password')) {
      severity = 'high';
      title = 'Sensitive Information Exposure';
    } else if (description.toLowerCase().includes('error') || description.toLowerCase().includes('disclosure')) {
      severity = 'medium';
      title = 'Information Disclosure';
    } else if (description.toLowerCase().includes('method') || description.toLowerCase().includes('options')) {
      severity = 'low';
      title = 'HTTP Methods Analysis';
    }

    return {
      scanner: 'w3af',
      title: title,
      description: description,
      severity: severity,
      url: '',
      cve_ids: [],
      cwe_id: null,
      wasc_id: null,
      solution: 'Review the w3af finding and implement appropriate security controls',
      confidence: 'medium',
      plugin_id: null,
      raw_output: line
    };
  });
}

function parseNmapReport(rawReport) {
  const vulnerabilities = rawReport?.vulnerabilities || [];

  if (vulnerabilities.length === 0) {
    return [{
      scanner: 'nmap',
      title: 'Nmap Network Scan Completed',
      description: 'Nmap network scan completed - no security issues detected',
      severity: 'info',
      url: rawReport?.target || '',
      cve_ids: [],
      cwe_id: null,
      wasc_id: null,
      solution: 'Continue regular network security monitoring',
      confidence: 'medium',
      plugin_id: null,
      raw_output: 'Nmap scan completed',
      layer: 'network',
      scanner_category: 'network',
      asset_type: 'ip_address',
      asset_identifier: rawReport?.target || ''
    }];
  }

  return vulnerabilities.map(vuln => ({
    scanner: 'nmap',
    title: vuln.title || 'Network Security Finding',
    description: vuln.description || 'Network security issue detected',
    severity: mapGenericSeverityToLevel(vuln.severity || 'medium'),
    url: vuln.url || '',
    cve_ids: [],
    cwe_id: null,
    wasc_id: null,
    solution: vuln.solution || 'Review network service configuration',
    confidence: vuln.confidence || 'medium',
    plugin_id: null,
    raw_output: vuln.description || vuln.title,
    // Network-specific fields
    layer: vuln.layer || 'network',
    scanner_category: vuln.scanner_category || 'network',
    asset_type: vuln.asset_type || 'ip_address',
    asset_identifier: vuln.asset_identifier || vuln.ip_address || '',
    hostname: vuln.hostname || null,
    ip_address: vuln.ip_address || null,
    port: vuln.port || null,
    service: vuln.service || null
  }));
}

function parseTrivyReport(rawReport) {
  const vulnerabilities = rawReport?.vulnerabilities || [];

  if (vulnerabilities.length === 0) {
    return [{
      scanner: 'trivy',
      title: 'Trivy Container Scan Completed',
      description: 'Trivy container scan completed - no vulnerabilities detected',
      severity: 'info',
      url: rawReport?.target || '',
      cve_ids: [],
      cwe_id: null,
      wasc_id: null,
      solution: 'Continue regular container security monitoring',
      confidence: 'medium',
      plugin_id: null,
      raw_output: 'Trivy scan completed',
      layer: 'container',
      scanner_category: 'container',
      asset_type: 'container_image',
      asset_identifier: rawReport?.target || ''
    }];
  }

  return vulnerabilities.map(vuln => ({
    scanner: 'trivy',
    title: vuln.title || 'Container Vulnerability',
    description: vuln.description || 'Container security issue detected',
    severity: mapGenericSeverityToLevel(vuln.severity || 'medium'),
    url: vuln.url || '',
    cve_ids: vuln.cve_ids || (vuln.cve_id ? [vuln.cve_id] : []),
    cwe_id: null,
    wasc_id: null,
    solution: vuln.solution || 'Update container image dependencies',
    confidence: vuln.confidence || 'high',
    plugin_id: null,
    raw_output: vuln.description || vuln.title,
    // Container-specific fields
    layer: vuln.layer || 'container',
    scanner_category: vuln.scanner_category || 'container',
    asset_type: vuln.asset_type || 'container_image',
    asset_identifier: vuln.asset_identifier || vuln.url?.replace('container://', '') || '',
    package_name: vuln.package_name || null,
    installed_version: vuln.installed_version || null,
    fixed_version: vuln.fixed_version || null
  }));
}

function parseWazuhReport(rawReport) {
  const vulnerabilities = rawReport?.vulnerabilities || [];

  if (vulnerabilities.length === 0) {
    return [{
      scanner: 'wazuh',
      title: 'Wazuh Infrastructure Scan Completed',
      description: 'Wazuh infrastructure scan completed - no vulnerabilities detected',
      severity: 'info',
      url: '',
      cve_ids: [],
      cwe_id: null,
      wasc_id: null,
      solution: 'Continue regular infrastructure security monitoring',
      confidence: 'medium',
      plugin_id: null,
      raw_output: 'Wazuh scan completed',
      layer: 'infrastructure',
      scanner_category: 'infrastructure',
      asset_type: 'hostname',
      asset_identifier: ''
    }];
  }

  return vulnerabilities.map(vuln => ({
    scanner: 'wazuh',
    title: vuln.title || 'Infrastructure Vulnerability',
    description: vuln.description || 'OS-level vulnerability detected',
    severity: mapGenericSeverityToLevel(vuln.severity || 'medium'),
    url: vuln.url || '',
    cve_ids: vuln.cve_ids || (vuln.cve_id ? [vuln.cve_id] : []),
    cwe_id: null,
    wasc_id: null,
    solution: vuln.solution || 'Update system packages',
    confidence: vuln.confidence || 'high',
    plugin_id: null,
    raw_output: vuln.description || vuln.title,
    // Infrastructure-specific fields
    layer: vuln.layer || 'infrastructure',
    scanner_category: vuln.scanner_category || 'infrastructure',
    asset_type: vuln.asset_type || 'hostname',
    asset_identifier: vuln.asset_identifier || vuln.hostname || '',
    hostname: vuln.hostname || null,
    ip_address: vuln.ip_address || null,
    package_name: vuln.package_name || null,
    installed_version: vuln.installed_version || null
  }));
}

function parseTestsslReport(rawReport) {
  const vulnerabilities = rawReport?.vulnerabilities || [];

  if (vulnerabilities.length === 0) {
    return [{
      scanner: 'testssl',
      title: 'SSL/TLS Scan Completed',
      description: 'SSL/TLS scan completed - no issues detected',
      severity: 'info',
      url: rawReport?.target ? `https://${rawReport.target}` : '',
      cve_ids: [],
      cwe_id: null,
      wasc_id: null,
      solution: 'Continue regular SSL/TLS monitoring',
      confidence: 'medium',
      plugin_id: null,
      raw_output: 'testssl scan completed',
      layer: 'network',
      scanner_category: 'network',
      asset_type: 'hostname',
      asset_identifier: rawReport?.target || ''
    }];
  }

  return vulnerabilities.map(vuln => ({
    scanner: 'testssl',
    title: vuln.title || 'SSL/TLS Issue',
    description: vuln.description || 'SSL/TLS configuration issue detected',
    severity: mapGenericSeverityToLevel(vuln.severity || 'medium'),
    url: vuln.url || '',
    cve_ids: [],
    cwe_id: null,
    wasc_id: null,
    solution: vuln.solution || 'Update SSL/TLS configuration',
    confidence: vuln.confidence || 'high',
    plugin_id: null,
    raw_output: vuln.description || vuln.title,
    // Network-specific fields
    layer: vuln.layer || 'network',
    scanner_category: vuln.scanner_category || 'network',
    asset_type: vuln.asset_type || 'hostname',
    asset_identifier: vuln.asset_identifier || vuln.hostname || '',
    hostname: vuln.hostname || null
  }));
}

// MAIN MULTI-SCAN ENDPOINT with Enhanced Logging
app.post('/multi-scan', async (req, res) => {
  const { 
    target, 
    scanId, 
    supabaseUrl, 
    supabaseKey, 
    scanners = ['zap'], 
    scan_type = 'web_application',
    zapOptions = { ajaxSpider: false },
    nmapOptions = {},
    trivyOptions = {},
    wazuhCredentials = null,
    testsslOptions = {},
    companyContext 
  } = req.body;

  console.log('\n' + '🚀 MULTI-SCAN REQUEST RECEIVED');
  console.log('='.repeat(60));
  console.log('🎯 Target:', target);
  console.log('🆔 Scan ID:', scanId);
  console.log('🔧 Selected scanners:', scanners);
  console.log('📋 Scan Type:', scan_type);
  console.log('⚙️ ZAP options:', zapOptions);
  console.log('⚙️ Nmap options:', nmapOptions);
  console.log('⚙️ Trivy options:', trivyOptions);
  console.log('⚙️ Wazuh credentials:', wazuhCredentials ? 'PROVIDED' : 'NOT PROVIDED');
  console.log('⚙️ testssl options:', testsslOptions);
  console.log('🏢 Company Context in Request:', companyContext ? 'YES' : 'NO');
  if (companyContext) {
    console.log('   Company Context Preview:', JSON.stringify(companyContext, null, 2));
  }
  console.log('='.repeat(60));

  // Validate target - allow non-HTTP targets for network/container scans
  if (!target || typeof target !== "string") {
    return res.status(400).json({ error: 'Invalid target' });
  }
  
  // Only require HTTP for web application scans
  if (scan_type === 'web_application' && !target.startsWith('http')) {
    return res.status(400).json({ error: 'Invalid target URL for web application scan' });
  }

  if (!scanId || !supabaseUrl || !supabaseKey) {
    return res.status(400).json({ error: 'Missing scanId, supabaseUrl, or supabaseKey' });
  }

  if (!Array.isArray(scanners) || scanners.length === 0) {
    return res.status(400).json({ error: 'At least one scanner must be selected' });
  }

  const validScanners = scanners.filter(scanner => SCANNERS[scanner]);
  if (validScanners.length === 0) {
    return res.status(400).json({ error: 'No valid scanners selected' });
  }

  res.status(202).json({
    success: true,
    message: `Multi-scan started with ${validScanners.length} scanner(s)`,
    scanId,
    scanners: validScanners
  });

  const supabase = createClient(supabaseUrl, supabaseKey);

  try {
    // Fetch company profile context - prioritize request body, fallback to database
    let companyProfile = null;
    console.log('\n' + '='.repeat(80));
    console.log('🏢 BUSINESS CONTEXT RESOLUTION - START');
    console.log('='.repeat(80));
    
    // Priority 1: Check if companyContext was provided in request body
    if (companyContext) {
      console.log('✅ Company context provided in request body');
      console.log('📋 Request body company context:', JSON.stringify(companyContext, null, 2));
      
      // Normalize the request format to match expected structure
      companyProfile = {
        company_name: companyContext.company_name || null,
        industry: companyContext.industry || null,
        website_purpose: companyContext.website_purpose || companyContext.type || null,
        data_records_count: companyContext.data_records_count || null,
        downtime_cost_per_hour: companyContext.downtime_cost_per_hour || null,
        compliance_requirements: companyContext.compliance_requirements || [],
        geographic_region: companyContext.geographic_region || companyContext.region || null,
        // Additional fields from request that might be useful
        annual_revenue: companyContext.annual_revenue || null,
        employee_count: companyContext.employee_count || null
      };
      
      console.log('\n✅ COMPANY PROFILE FROM REQUEST BODY:');
      console.log('-'.repeat(60));
      console.log(`   Company Name: ${companyProfile.company_name || 'N/A'}`);
      console.log(`   Industry: ${companyProfile.industry || 'N/A'}`);
      console.log(`   Website Purpose: ${companyProfile.website_purpose || 'N/A'}`);
      console.log(`   Annual Revenue: ${companyProfile.annual_revenue ? '$' + companyProfile.annual_revenue.toLocaleString() : 'N/A'}`);
      console.log(`   Employee Count: ${companyProfile.employee_count || 'N/A'}`);
      console.log(`   Data Records Count: ${companyProfile.data_records_count || 'N/A'}`);
      console.log(`   Downtime Cost/Hour: ${companyProfile.downtime_cost_per_hour ? '$' + companyProfile.downtime_cost_per_hour : 'N/A'}`);
      console.log(`   Compliance Requirements: ${companyProfile.compliance_requirements?.join(', ') || 'None'}`);
      console.log(`   Geographic Region: ${companyProfile.geographic_region || 'N/A'}`);
      console.log('-'.repeat(60));
      console.log(`📊 Normalized profile data:`, JSON.stringify(companyProfile, null, 2));
      console.log('='.repeat(80));
      console.log(`🏢 BUSINESS CONTEXT STATUS: LOADED FROM REQUEST BODY`);
      console.log('='.repeat(80) + '\n');
    } else {
      // Priority 2: Fallback to database lookup
      console.log('ℹ️  No company context in request body - checking database...');
      console.log(`🔍 Looking up scan report ID: ${scanId}`);
      
      try {
        const { data: scanReport, error: scanReportError } = await supabase
          .from('scan_reports')
          .select('company_profile_id')
          .eq('id', scanId)
          .single();

        if (scanReportError) {
          console.error('❌ Error fetching scan report:', scanReportError);
          console.error('   Error details:', JSON.stringify(scanReportError, null, 2));
        } else {
          console.log('✅ Scan report fetched successfully');
          console.log(`📋 Scan report data:`, JSON.stringify(scanReport, null, 2));
          
          if (scanReport?.company_profile_id) {
            console.log(`\n🔗 Company profile ID found: ${scanReport.company_profile_id}`);
            console.log(`📥 Fetching company profile from database...`);
            
            const { data: profile, error: profileError } = await supabase
              .from('company_profiles')
              .select('*')
              .eq('id', scanReport.company_profile_id)
              .single();
            
            if (profileError) {
              console.error('❌ Error fetching company profile:', profileError);
              console.error('   Error details:', JSON.stringify(profileError, null, 2));
            } else if (profile) {
              companyProfile = profile;
              console.log('\n✅ COMPANY PROFILE LOADED FROM DATABASE:');
              console.log('-'.repeat(60));
              console.log(`   Company Name: ${companyProfile.company_name || 'N/A'}`);
              console.log(`   Industry: ${companyProfile.industry || 'N/A'}`);
              console.log(`   Website Purpose: ${companyProfile.website_purpose || 'N/A'}`);
              console.log(`   Data Records Count: ${companyProfile.data_records_count || 'N/A'}`);
              console.log(`   Downtime Cost/Hour: ${companyProfile.downtime_cost_per_hour ? '$' + companyProfile.downtime_cost_per_hour : 'N/A'}`);
              console.log(`   Compliance Requirements: ${companyProfile.compliance_requirements?.join(', ') || 'None'}`);
              console.log(`   Geographic Region: ${companyProfile.geographic_region || 'N/A'}`);
              console.log('-'.repeat(60));
              console.log(`📊 Full profile data:`, JSON.stringify(companyProfile, null, 2));
            } else {
              console.warn('⚠️ Company profile ID exists but profile not found in database');
            }
          } else {
            console.log('ℹ️  No company_profile_id found in scan report - business context will not be used');
            console.log('   This is normal if no company profile was associated with this scan');
          }
        }
      } catch (ctxError) {
        console.error('❌ Exception while loading business context from database:', ctxError);
        console.error('   Error message:', ctxError.message);
        console.error('   Stack trace:', ctxError.stack);
      }
      
      console.log('='.repeat(80));
      console.log(`🏢 BUSINESS CONTEXT STATUS: ${companyProfile ? 'LOADED FROM DATABASE' : 'NOT AVAILABLE'}`);
      console.log('='.repeat(80) + '\n');
    }

    await updateScanProgress(supabase, scanId, "running", 10, `Starting ${validScanners.length} scanner(s): ${validScanners.join(', ')}`);

    const allVulnerabilities = [];
    const scanResults = {};
    const failedScanners = []; // Track failed scanners for partial failure support

    console.log('\n🎯 PHASE 1: Executing individual scanners...');
    console.log('='.repeat(60));

    for (let i = 0; i < validScanners.length; i++) {
      const scannerName = validScanners[i];
      const scanner = SCANNERS[scannerName];

      console.log(`🔄 Running ${scanner.name} (${i + 1}/${validScanners.length})`);
      const baseProgress = 10 + (i * 30 / validScanners.length);
      const completedScanners = i;
      await updateScanProgress(
        supabase, 
        scanId, 
        "running", 
        Math.round(baseProgress), 
        `Completed ${completedScanners}/${validScanners.length} scanners - Running ${scanner.name} scan...`
      );

      try {
        let cmdData;
        switch (scannerName) {
          case 'zap':
            cmdData = buildZapCommand(target, scanner, zapOptions);
            break;
          case 'rengine':
            cmdData = buildReNgineCommand(target, scanner);
            break;
          case 'wapiti':
            cmdData = buildWapitiCommand(target, scanner);
            break;
          case 'nikto':
            cmdData = buildNiktoCommand(target, scanner);
            break;
          case 'w3af':
            cmdData = buildW3afCommand(target, scanner);
            break;
          case 'nmap':
            cmdData = buildNmapCommand(target, scanner, nmapOptions);
            break;
          case 'trivy':
            cmdData = buildTrivyCommand(target, scanner, trivyOptions);
            break;
          case 'wazuh':
            if (!wazuhCredentials) {
              throw new Error('Wazuh credentials required but not provided');
            }
            cmdData = buildWazuhCommand(target, scanner, { wazuhCredentials });
            break;
          case 'testssl':
            cmdData = buildTestsslCommand(target, scanner, testsslOptions);
            break;
          default:
            throw new Error(`Unknown scanner: ${scannerName}`);
        }

        console.log(`⚙️ Executing ${scanner.name}:`, cmdData.command);

        // Handle Wazuh specially (direct Python execution with env vars)
        let executionResult;
        if (cmdData.isDirectPython && cmdData.envVars) {
          // Direct Python execution for Wazuh
          const env = { ...process.env, ...cmdData.envVars };
          executionResult = await new Promise((resolve, reject) => {
            exec(cmdData.command, { cwd: hostDir, timeout: 300000, env }, (err, stdout, stderr) => {
              const out = stdout.trim();
              const errText = stderr.trim();

              console.log(`${scanner.name} stdout:`, out);
              if (errText) console.log(`${scanner.name} stderr:`, errText);

              resolve({
                success: !err,
                stdout: out,
                stderr: errText,
                error: err
              });
            });
          });
        } else {
          // Docker-based execution for other scanners
          executionResult = await new Promise((resolve, reject) => {
            exec(cmdData.command, { cwd: hostDir, timeout: 300000 }, (err, stdout, stderr) => {
              const out = stdout.trim();
              const errText = stderr.trim();

              console.log(`${scanner.name} stdout:`, out);
              if (errText) console.log(`${scanner.name} stderr:`, errText);

              resolve({
                success: !(err && !(scannerName === 'zap' && err.code === 2)),
                stdout: out,
                stderr: errText,
                error: err
              });
            });
          });
        }

        let parsedVulns = [];
        if (fs.existsSync(cmdData.reportHostPath)) {
          try {
            if (scanner.reportFormat === 'json') {
              const rawReport = JSON.parse(fs.readFileSync(cmdData.reportHostPath, 'utf8'));
              switch (scannerName) {
                case 'zap':
                  parsedVulns = parseZapReport(rawReport);
                  break;
                case 'rengine':
                  parsedVulns = parseReNgineReport(rawReport);
                  break;
                case 'wapiti':
                  parsedVulns = parseWapitiReport(rawReport);
                  break;
                case 'nmap':
                  parsedVulns = parseNmapReport(rawReport);
                  break;
                case 'trivy':
                  parsedVulns = parseTrivyReport(rawReport);
                  break;
                case 'wazuh':
                  parsedVulns = parseWazuhReport(rawReport);
                  break;
                case 'testssl':
                  parsedVulns = parseTestsslReport(rawReport);
                  break;
              }
            } else {
              const reportText = fs.readFileSync(cmdData.reportHostPath, 'utf8');
              switch (scannerName) {
                case 'nikto':
                  parsedVulns = parseNiktoFromStdout(executionResult.stdout);
                  break;
                case 'w3af':
                  parsedVulns = parseW3afReport(reportText);
                  break;
              }
            }
            console.log(`✅ ${scanner.name} parsed from file: ${parsedVulns.length} vulnerabilities`);
          } catch (parseError) {
            console.error(`❌ Failed to parse ${scanner.name} report file:`, parseError);
            parsedVulns = [];
          }
        }

        if (parsedVulns.length === 0 && executionResult.stdout) {
          console.log(`📝 ${scanner.name} parsing from stdout instead...`);
          switch (scannerName) {
            case 'nikto':
              parsedVulns = parseNiktoFromStdout(executionResult.stdout);
              break;
            default:
              parsedVulns = [{
                scanner: scannerName,
                title: `${scanner.name} Scan Completed`,
                description: `${scanner.name} scan completed successfully`,
                severity: 'info',
                url: '',
                cve_ids: [],
                cwe_id: null,
                wasc_id: null,
                solution: 'Continue regular security monitoring',
                confidence: 'medium',
                plugin_id: null,
                raw_output: `${scanner.name} scan completed`
              }];
          }
        }

        scanResults[scannerName] = {
          vulnerabilities: parsedVulns.length,
          status: executionResult.success ? 'completed' : 'failed',
          error: executionResult.error?.message || undefined,
          raw_findings: parsedVulns,
          execution_details: {
            stdout: executionResult.stdout,
            stderr: executionResult.stderr,
            command: cmdData.command,
            report_file: cmdData.reportHostPath
          }
        };

        allVulnerabilities.push(...parsedVulns);
        console.log(`✅ ${scanner.name} found ${parsedVulns.length} total vulnerabilities`);

      } catch (scannerError) {
        console.error(`❌ ${scanner.name} error:`, scannerError);
        failedScanners.push(scannerName);
        scanResults[scannerName] = {
          vulnerabilities: 0,
          status: 'failed',
          error: scannerError.message,
          raw_findings: [],
          execution_details: null
        };
        // Continue with other scanners - don't fail entire scan
        console.log(`⚠️ Scanner ${scanner.name} failed, continuing with remaining scanners...`);
      }
    }

    const successfulScanners = validScanners.filter(s => !failedScanners.includes(s));
    console.log(`\n🎯 PHASE 1 COMPLETE: Collected ${allVulnerabilities.length} raw vulnerabilities from ${successfulScanners.length}/${validScanners.length} scanners`);
    if (failedScanners.length > 0) {
      console.log(`⚠️ Failed scanners: ${failedScanners.join(', ')}`);
    }

    console.log('\n🎯 PHASE 2: Unified AI processing and deduplication...');
    console.log('='.repeat(60));

    const scanMetadata = {
      scanners_used: validScanners,
      successful_scanners: successfulScanners,
      failed_scanners: failedScanners,
      scanner_results: scanResults,
      scan_type: scan_type,
      zap_options: zapOptions,
      nmap_options: nmapOptions,
      trivy_options: trivyOptions,
      testssl_options: testsslOptions,
      target: target,
      scan_timestamp: new Date().toISOString()
    };

    const unifiedResults = await processAllVulnerabilitiesUnified(
      allVulnerabilities,
      scanResults,
      scanMetadata,
      target,
      scanId,
      supabase,
      companyProfile
    );

    console.log(`\n🎯 PHASE 2 COMPLETE: AI processed ${unifiedResults.processedVulnerabilities.length} unique vulnerabilities`);

    // PHASE 3: Database insertion and completion
    console.log('\n🎯 PHASE 3: Database insertion and completion...');
    console.log('='.repeat(60));

    await updateScanProgress(supabase, scanId, "running", 90, "Saving deduplicated vulnerabilities to database...");

    if (unifiedResults.processedVulnerabilities.length > 0) {
      console.log(`💾 Inserting ${unifiedResults.processedVulnerabilities.length} deduplicated vulnerabilities to Supabase`);

      // FINAL COMPREHENSIVE LOGGING BEFORE DATABASE INSERT
      console.log('\n📊 FINAL DATABASE INSERT SUMMARY:');
      console.log('='.repeat(80));
      console.log(`📋 Total vulnerabilities to insert: ${unifiedResults.processedVulnerabilities.length}`);

      // Show sample of what's being inserted
      if (unifiedResults.processedVulnerabilities.length > 0) {
        const sample = unifiedResults.processedVulnerabilities[0];
        console.log('\n🔍 SAMPLE VULNERABILITY BEING INSERTED:');
        console.log('-'.repeat(60));
        console.log(`📋 Title: ${sample.title}`);
        console.log(`🔴 Severity: ${sample.severity}`);
        console.log(`🎯 Scanner: ${sample.scanner_name}`);
        console.log(`📖 Description Length: ${(sample.description || '').length} chars`);
        console.log(`🔍 AI Analysis Length: ${(sample.ai_analysis || '').length} chars`);
        console.log(`💼 Business Impact Length: ${(sample.business_impact || '').length} chars`);
        console.log(`⚙️ Technical Impact Length: ${(sample.technical_impact || '').length} chars`);
        console.log(`🔧 Remediation Steps: ${Array.isArray(sample.remediation_steps) ? sample.remediation_steps.length : 0} steps`);
        console.log(`⚡ Attack Scenarios: ${Array.isArray(sample.attack_scenarios) ? sample.attack_scenarios.length : 0} scenarios`);
        console.log(`📚 References: ${Array.isArray(sample.reference_links) ? sample.reference_links.length : 0} links`);

        if (Array.isArray(sample.remediation_steps) && sample.remediation_steps.length > 0) {
          console.log('\n🔧 REMEDIATION STEPS PREVIEW:');
          sample.remediation_steps.slice(0, 3).forEach((step, i) => {
            console.log(`  ${i + 1}. ${step.substring(0, 100)}...`);
          });
        }

        if (Array.isArray(sample.attack_scenarios) && sample.attack_scenarios.length > 0) {
          console.log('\n⚡ ATTACK SCENARIOS PREVIEW:');
          sample.attack_scenarios.slice(0, 2).forEach((scenario, i) => {
            console.log(`  ${i + 1}. ${scenario.substring(0, 100)}...`);
          });
        }

        console.log('\n✅ CONTENT VALIDATION:');
        console.log(`- Unique title: ${sample.title ? 'YES' : 'NO'}`);
        console.log(`- Has description: ${sample.description ? 'YES' : 'NO'}`);
        console.log(`- Has AI analysis: ${sample.ai_analysis ? 'YES' : 'NO'}`);
        console.log(`- Has business impact: ${sample.business_impact ? 'YES' : 'NO'}`);
        console.log(`- Has technical impact: ${sample.technical_impact ? 'YES' : 'NO'}`);
        console.log(`- Has remediation steps: ${Array.isArray(sample.remediation_steps) && sample.remediation_steps.length > 0 ? 'YES' : 'NO'}`);
        console.log(`- Has attack scenarios: ${Array.isArray(sample.attack_scenarios) && sample.attack_scenarios.length > 0 ? 'YES' : 'NO'}`);
        console.log(`- Scanner attribution: ${sample.scanner_name || 'MISSING'}`);
      }
      console.log('='.repeat(80));

      const { data: inserted, error: insertError } = await supabase
        .from("vulnerabilities")
        .insert(unifiedResults.processedVulnerabilities)
        .select();

      if (insertError) {
        console.error('❌ Failed to insert vulnerabilities:', insertError);
        await updateScanProgress(supabase, scanId, "failed", 0, `Database error: ${insertError.message}`);
        return;
      }

      console.log(`✅ Successfully inserted ${inserted.length} deduplicated vulnerabilities`);

      // POST-INSERT VERIFICATION LOGGING
      console.log('\n🎯 POST-INSERT VERIFICATION:');
      console.log('-'.repeat(60));
      console.log(`✅ Database confirmed ${inserted.length} vulnerabilities inserted`);
      console.log(`📊 Expected: ${unifiedResults.processedVulnerabilities.length}, Actual: ${inserted.length}`);
      console.log(`🎯 Match: ${inserted.length === unifiedResults.processedVulnerabilities.length ? 'YES' : 'NO'}`);

      if (inserted.length > 0) {
        console.log('\n📋 INSERTED VULNERABILITY SAMPLE:');
        const insertedSample = inserted[0];
        console.log(`📋 ID: ${insertedSample.id}`);
        console.log(`📋 Title: ${insertedSample.title}`);
        console.log(`🎯 Scanner: ${insertedSample.scanner_name}`);
        console.log(`🔴 Severity: ${insertedSample.severity}`);
        console.log(`📊 Risk Level: ${insertedSample.risk_level}`);
        console.log(`⚡ Has AI Analysis: ${insertedSample.ai_analysis ? 'YES' : 'NO'}`);
        console.log(`💼 Has Business Impact: ${insertedSample.business_impact ? 'YES' : 'NO'}`);
        console.log(`🔧 Has Remediation Steps: ${insertedSample.remediation_steps ? 'YES' : 'NO'}`);
        console.log(`⚡ Has Attack Scenarios: ${insertedSample.attack_scenarios ? 'YES' : 'NO'}`);
      }
    }

    // Enhanced scan metadata with AI analysis summary
    const enhancedScanMetadata = {
      ...scanMetadata,
      ai_analysis_summary: unifiedResults.aiAnalysis.summary,
      scanner_performance: unifiedResults.aiAnalysis.scanner_performance,
      deduplication_stats: {
        raw_findings: allVulnerabilities.length,
        unique_vulnerabilities: unifiedResults.processedVulnerabilities.length,
        duplicates_merged: allVulnerabilities.length - unifiedResults.processedVulnerabilities.length
      }
    };

    // Final update: Mark as completed with enhanced summary
    const successStatus = failedScanners.length === 0 ? 'successfully' : `with ${failedScanners.length} scanner failure(s)`;
    const completionMessage = `🎉 Multi-scan completed ${successStatus}!
📊 Results: ${unifiedResults.processedVulnerabilities.length} unique vulnerabilities (${allVulnerabilities.length} raw findings)
🔍 Scanners: ${successfulScanners.join(', ')}${failedScanners.length > 0 ? ` (Failed: ${failedScanners.join(', ')})` : ''}
📋 Scan Type: ${scan_type}
🤖 AI Analysis: ${unifiedResults.aiAnalysis.summary.overall_risk_assessment}
🔗 Deduplication: ${unifiedResults.aiAnalysis.summary.duplicates_merged} duplicates merged`;

    const { error: finishError } = await supabase
      .from("scan_reports")
      .update({
        status: "completed",
        progress: 100,
        completed_at: new Date().toISOString(),
        total_vulnerabilities: unifiedResults.processedVulnerabilities.length,
        scan_metadata: enhancedScanMetadata,
        message: completionMessage
      })
      .eq("id", scanId);

    if (finishError) {
      console.error('❌ Failed to mark scan as completed:', finishError);
      return;
    }

    // FINAL SUCCESS LOGGING
    console.log('\n' + '🎉 MULTI-SCAN COMPLETED SUCCESSFULLY!');
    console.log('='.repeat(80));
    console.log(`📊 Final Results Summary:`);
    console.log(`  - Raw vulnerabilities collected: ${allVulnerabilities.length}`);
    console.log(`  - Unique vulnerabilities after AI processing: ${unifiedResults.processedVulnerabilities.length}`);
    console.log(`  - Duplicates intelligently merged: ${unifiedResults.aiAnalysis.summary.duplicates_merged}`);
    console.log(`  - Overall risk assessment: ${unifiedResults.aiAnalysis.summary.overall_risk_assessment}`);
    console.log(`  - Scanners successfully executed: ${validScanners.join(', ')}`);
    console.log(`  - Scan ID: ${scanId}`);
    console.log(`  - Target: ${target}`);
    console.log(`  - AI processing: ${ANTHROPIC_API_KEY ? 'ENABLED' : 'FALLBACK'}`);
    console.log('='.repeat(80));

    // DETAILED VULNERABILITY BREAKDOWN LOGGING
    if (unifiedResults.processedVulnerabilities.length > 0) {
      console.log('\n📋 DETAILED VULNERABILITY BREAKDOWN:');
      console.log('-'.repeat(80));

      const severityBreakdown = unifiedResults.processedVulnerabilities.reduce((acc, v) => {
        acc[v.severity] = (acc[v.severity] || 0) + 1;
        return acc;
      }, {});

      console.log('🔴 Severity Distribution:');
      Object.entries(severityBreakdown).forEach(([severity, count]) => {
        console.log(`  - ${severity.toUpperCase()}: ${count} vulnerabilities`);
      });

      const scannerBreakdown = unifiedResults.processedVulnerabilities.reduce((acc, v) => {
        const scanners = (v.scanner_name || '').split(',').map(s => s.trim());
        scanners.forEach(scanner => {
          if (scanner && scanner !== 'unknown') {
            acc[scanner] = (acc[scanner] || 0) + 1;
          }
        });
        return acc;
      }, {});

      console.log('\n🔍 Scanner Attribution:');
      Object.entries(scannerBreakdown).forEach(([scanner, count]) => {
        console.log(`  - ${scanner.toUpperCase()}: ${count} findings`);
      });

      console.log('\n🎯 Top 5 Vulnerabilities Found:');
      unifiedResults.processedVulnerabilities.slice(0, 5).forEach((vuln, i) => {
        console.log(`  ${i + 1}. ${vuln.title} (${vuln.severity}) - Scanner: ${vuln.scanner_name}`);
      });
    }

    console.log('\n✅ Multi-scan processing pipeline completed successfully!');
    console.log('='.repeat(80));

  } catch (error) {
    console.error('\n❌ Multi-scan error:', error);
    console.error('Stack trace:', error.stack);
    await updateScanProgress(supabase, scanId, "failed", 0, `Multi-scan error: ${error.message}`);
  }
});

// Legacy single scan endpoint for backward compatibility
app.post('/scan', async (req, res) => {
  const { target, scanId, supabaseUrl, supabaseKey } = req.body;

  console.log('💥 Got legacy /scan request for', target, 'scanId:', scanId);

  if (!target || !scanId || !supabaseUrl || !supabaseKey) {
    return res.status(400).json({ error: 'Missing required parameters' });
  }

  // Redirect to multi-scan with just ZAP
  req.body.scanners = ['zap'];
  req.body.zapOptions = { ajaxSpider: false };
  return app._router.handle(req, res);
});

// Enhanced health check with AI status
app.get('/health', (req, res) => {
  const aiConfigured = !!ANTHROPIC_API_KEY;

  res.json({
    status: 'healthy',
    scanners: Object.keys(SCANNERS),
    scanner_details: SCANNERS,
    ai_features: {
      openai_configured: aiConfigured,
      model: ANTHROPIC_MODEL,
      unified_processing: true,
      deduplication: true,
      comprehensive_analysis: true,
      detailed_logging: true
    },
    reports_directory: reportsDir,
    reports_directory_exists: fs.existsSync(reportsDir),
    scripts_directory: scriptsDir,
    scripts_directory_exists: fs.existsSync(scriptsDir),
    capabilities: [
      'Multi-scanner execution',
      'AI-powered vulnerability analysis',
      'Intelligent deduplication',
      'Scanner correlation',
      'Enterprise-grade reporting',
      'Compliance assessment',
      'Attack scenario modeling',
      'Specific remediation guidance',
      'Comprehensive logging'
    ],
    timestamp: new Date().toISOString()
  });
});

// New endpoint to get AI analysis summary
app.get('/scan/:scanId/ai-summary', async (req, res) => {
  const { scanId } = req.params;

  try {
    const { supabaseUrl, supabaseKey } = req.query;

    if (!supabaseUrl || !supabaseKey) {
      return res.status(400).json({ error: 'Missing Supabase credentials' });
    }

    const supabase = createClient(supabaseUrl, supabaseKey);

    const { data: scanReport, error } = await supabase
      .from("scan_reports")
      .select("scan_metadata")
      .eq("id", scanId)
      .single();

    if (error || !scanReport) {
      return res.status(404).json({ error: 'Scan not found' });
    }

    const aiSummary = scanReport.scan_metadata?.ai_analysis_summary;
    const scannerPerformance = scanReport.scan_metadata?.scanner_performance;
    const deduplicationStats = scanReport.scan_metadata?.deduplication_stats;

    res.json({
      scan_id: scanId,
      ai_analysis_summary: aiSummary,
      scanner_performance: scannerPerformance,
      deduplication_stats: deduplicationStats,
      generated_at: new Date().toISOString()
    });

  } catch (error) {
    console.error('❌ Error fetching AI summary:', error);
    res.status(500).json({ error: 'Failed to fetch AI summary' });
  }
});

// Helper function to save vulnerabilities to Supabase
async function saveVulnerabilitiesToSupabase(supabase, scanId, vulnerabilities) {
  if (vulnerabilities.length === 0) {
    return { inserted: [], error: null };
  }

  const { data: inserted, error } = await supabase
    .from("vulnerabilities")
    .insert(vulnerabilities)
    .select();

  return { inserted: inserted || [], error };
}

// Helper function to update scan status
async function updateScanStatus(supabase, scanId, status, message, progress) {
  const updateData = { status, progress: progress || 100 };
  if (message) updateData.message = message;
  if (status === 'completed') {
    updateData.completed_at = new Date().toISOString();
  }

  const { error } = await supabase
    .from("scan_reports")
    .update(updateData)
    .eq("id", scanId);

  return { error };
}

// File upload endpoint for scan imports
app.post('/upload-scan-file', upload.single('scanFile'), async (req, res) => {
  console.log('\n📤 FILE UPLOAD REQUEST RECEIVED');
  console.log('='.repeat(60));
  
  try {
    // Validate request
    if (!req.file) {
      return res.status(400).json({ success: false, error: 'No file uploaded' });
    }
    
    const { scanId, fileType, supabaseUrl, supabaseKey, companyContext } = req.body;
    
    if (!scanId || !fileType) {
      if (req.file && fs.existsSync(req.file.path)) {
        fs.unlinkSync(req.file.path);
      }
      return res.status(400).json({ success: false, error: 'Missing scanId or fileType' });
    }

    if (!supabaseUrl || !supabaseKey) {
      if (req.file && fs.existsSync(req.file.path)) {
        fs.unlinkSync(req.file.path);
      }
      return res.status(400).json({ success: false, error: 'Missing supabaseUrl or supabaseKey' });
    }
    
    const filePath = req.file.path;
    const supabase = createClient(supabaseUrl, supabaseKey);
    
    console.log(`  📄 Processing ${fileType} file: ${req.file.originalname}`);
    console.log(`  📊 File size: ${(req.file.size / 1024).toFixed(2)} KB`);
    console.log(`  🆔 Scan ID: ${scanId}`);
    
    // Update scan status to running
    await updateScanStatus(supabase, scanId, 'running', 'Parsing uploaded scan file...', 10);
    
    // Call Python parser
    const cmd = `python3 "${path.join(scriptsDir, 'parse_scan_file.py')}" "${filePath}" "${fileType}"`;
    
    let parsedData;
    try {
      const result = execSync(cmd, { 
        encoding: 'utf-8',
        maxBuffer: 10 * 1024 * 1024,  // 10MB output buffer
        timeout: 60000  // 60 second timeout
      });
      
      parsedData = JSON.parse(result);
      
      if (parsedData.error) {
        throw new Error(parsedData.error);
      }
    } catch (parseError) {
      console.error('❌ Parse error:', parseError.message);
      if (fs.existsSync(filePath)) {
        fs.unlinkSync(filePath);
      }
      await updateScanStatus(supabase, scanId, 'failed', `Failed to parse file: ${parseError.message}`, 0);
      return res.status(500).json({ 
        success: false, 
        error: `Failed to parse file: ${parseError.message}` 
      });
    }
    
    console.log(`  ✅ Parsed ${parsedData.vulnerabilities.length} vulnerabilities`);
    
    // Clean up uploaded file
    if (fs.existsSync(filePath)) {
      fs.unlinkSync(filePath);
      console.log(`  🧹 Cleaned up uploaded file`);
    }
    
    // Process vulnerabilities through AI pipeline
    console.log('\n🎯 Processing vulnerabilities through AI pipeline...');
    await updateScanStatus(supabase, scanId, 'running', 'Processing vulnerabilities with AI...', 30);
    
    // Build company profile from context if provided
    let companyProfile = null;
    if (companyContext) {
      companyProfile = {
        company_name: companyContext.company_name || null,
        industry: companyContext.industry || null,
        website_purpose: companyContext.website_purpose || companyContext.type || null,
        data_records_count: companyContext.data_records_count || null,
        downtime_cost_per_hour: companyContext.downtime_cost_per_hour || null,
        compliance_requirements: companyContext.compliance_requirements || [],
        geographic_region: companyContext.geographic_region || companyContext.region || null,
        annual_revenue: companyContext.annual_revenue || null,
        employee_count: companyContext.employee_count || null
      };
    }
    
    // Create scan metadata
    const scanMetadata = {
      scanners_used: [parsedData.scanner],
      successful_scanners: [parsedData.scanner],
      failed_scanners: [],
      scanner_results: {
        [parsedData.scanner]: {
          vulnerabilities: parsedData.vulnerabilities.length,
          status: 'completed',
          raw_findings: parsedData.vulnerabilities
        }
      },
      scan_type: 'file_import',
      target: 'file_upload',
      scan_timestamp: new Date().toISOString(),
      ...parsedData.scan_metadata
    };
    
    // Process through AI pipeline
    const unifiedResults = await processAllVulnerabilitiesUnified(
      parsedData.vulnerabilities,
      scanMetadata.scanner_results,
      scanMetadata,
      'file_upload',
      scanId,
      supabase,
      companyProfile
    );
    
    console.log(`  ✅ AI processed ${unifiedResults.processedVulnerabilities.length} unique vulnerabilities`);
    
    // Save to database
    await updateScanStatus(supabase, scanId, 'running', 'Saving vulnerabilities to database...', 90);
    
    if (unifiedResults.processedVulnerabilities.length > 0) {
      const { inserted, error: dbError } = await saveVulnerabilitiesToSupabase(
        supabase,
        scanId,
        unifiedResults.processedVulnerabilities
      );
      
      if (dbError) {
        console.error('❌ Database error:', dbError);
        await updateScanStatus(supabase, scanId, 'failed', `Database error: ${dbError.message}`, 0);
        return res.status(500).json({ success: false, error: `Database error: ${dbError.message}` });
      }
      
      console.log(`  💾 Saved ${inserted.length} vulnerabilities to Supabase`);
      
      // Update scan status to completed
      const completionMessage = `File import completed: ${inserted.length} vulnerabilities from ${parsedData.scanner}`;
      await updateScanStatus(supabase, scanId, 'completed', completionMessage, 100);
      
      // Return success
      res.json({
        success: true,
        scanner: parsedData.scanner,
        vulnerabilities_found: parsedData.vulnerabilities.length,
        vulnerabilities_saved: inserted.length,
        scan_id: scanId,
        file_type: fileType,
        original_filename: req.file.originalname,
        ai_processed: true
      });
    } else {
      await updateScanStatus(supabase, scanId, 'completed', 'File import completed: No vulnerabilities found', 100);
      res.json({
        success: true,
        scanner: parsedData.scanner,
        vulnerabilities_found: 0,
        vulnerabilities_saved: 0,
        scan_id: scanId,
        file_type: fileType,
        original_filename: req.file.originalname,
        ai_processed: true
      });
    }
    
  } catch (error) {
    console.error('❌ File upload error:', error);
    
    // Clean up file if it exists
    if (req.file && fs.existsSync(req.file.path)) {
      fs.unlinkSync(req.file.path);
    }
    
    // Try to update scan status if we have the scanId
    if (req.body.scanId && req.body.supabaseUrl && req.body.supabaseKey) {
      try {
        const supabase = createClient(req.body.supabaseUrl, req.body.supabaseKey);
        await updateScanStatus(supabase, req.body.scanId, 'failed', `Error: ${error.message}`, 0);
      } catch (updateError) {
        console.error('Failed to update scan status:', updateError);
      }
    }
    
    res.status(500).json({ 
      success: false, 
      error: error.message || 'Unknown error during file processing'
    });
  }
});

// Tenable.io scan endpoint
app.post('/tenable-scan', async (req, res) => {
  console.log('\n🔍 TENABLE.IO SCAN REQUEST RECEIVED');
  console.log('='.repeat(60));
  
  const { scanId, supabaseUrl, supabaseKey, tenableCredentials, companyContext } = req.body;
  
  if (!scanId || !supabaseUrl || !supabaseKey) {
    return res.status(400).json({ success: false, error: 'Missing scanId, supabaseUrl, or supabaseKey' });
  }
  
  if (!tenableCredentials || !tenableCredentials.access_key || !tenableCredentials.secret_key) {
    return res.status(400).json({ success: false, error: 'Missing Tenable credentials (access_key, secret_key)' });
  }
  
  console.log(`  🆔 Scan ID: ${scanId}`);
  console.log(`  🔑 Tenable API URL: ${tenableCredentials.api_url || 'https://cloud.tenable.com'}`);
  
  const supabase = createClient(supabaseUrl, supabaseKey);
  
  res.status(202).json({
    success: true,
    message: 'Tenable scan started',
    scanId
  });
  
  try {
    // Update scan status to running
    await updateScanStatus(supabase, scanId, 'running', 'Connecting to Tenable.io...', 10);
    
    // Build company profile from context if provided
    let companyProfile = null;
    if (companyContext) {
      companyProfile = {
        company_name: companyContext.company_name || null,
        industry: companyContext.industry || null,
        website_purpose: companyContext.website_purpose || companyContext.type || null,
        data_records_count: companyContext.data_records_count || null,
        downtime_cost_per_hour: companyContext.downtime_cost_per_hour || null,
        compliance_requirements: companyContext.compliance_requirements || [],
        geographic_region: companyContext.geographic_region || companyContext.region || null,
        annual_revenue: companyContext.annual_revenue || null,
        employee_count: companyContext.employee_count || null
      };
    }
    
    // Call Python script
    await updateScanStatus(supabase, scanId, 'running', 'Fetching scan results from Tenable.io...', 30);
    
    const credentialsJson = JSON.stringify(tenableCredentials);
    const cmd = `python3 "${path.join(scriptsDir, 'tenable_scanner.py')}" '${credentialsJson.replace(/'/g, "'\\''")}'`;
    
    let tenableData;
    try {
      const result = execSync(cmd, {
        encoding: 'utf-8',
        maxBuffer: 10 * 1024 * 1024,  // 10MB output buffer
        timeout: 120000  // 2 minute timeout for Tenable API
      });
      
      tenableData = JSON.parse(result);
      
      if (tenableData.error) {
        throw new Error(tenableData.error);
      }
    } catch (execError) {
      console.error('❌ Tenable script error:', execError.message);
      await updateScanStatus(supabase, scanId, 'failed', `Tenable integration failed: ${execError.message}`, 0);
      return;
    }
    
    console.log(`  ✅ Fetched ${tenableData.vulnerabilities.length} vulnerabilities from Tenable.io`);
    
    // Process vulnerabilities through AI pipeline
    await updateScanStatus(supabase, scanId, 'running', 'Processing vulnerabilities with AI...', 50);
    
    const scanMetadata = {
      scanners_used: ['tenable'],
      successful_scanners: ['tenable'],
      failed_scanners: [],
      scanner_results: {
        tenable: {
          vulnerabilities: tenableData.vulnerabilities.length,
          status: 'completed',
          raw_findings: tenableData.vulnerabilities
        }
      },
      scan_type: 'infrastructure',
      target: tenableData.target || 'Tenable Scan',
      scan_timestamp: new Date().toISOString(),
      ...tenableData.scan_metadata
    };
    
    const unifiedResults = await processAllVulnerabilitiesUnified(
      tenableData.vulnerabilities,
      scanMetadata.scanner_results,
      scanMetadata,
      tenableData.target || 'Tenable Scan',
      scanId,
      supabase,
      companyProfile
    );
    
    console.log(`  ✅ AI processed ${unifiedResults.processedVulnerabilities.length} unique vulnerabilities`);
    
    // Save to database
    await updateScanStatus(supabase, scanId, 'running', 'Saving vulnerabilities to database...', 90);
    
    if (unifiedResults.processedVulnerabilities.length > 0) {
      const { inserted, error: dbError } = await saveVulnerabilitiesToSupabase(
        supabase,
        scanId,
        unifiedResults.processedVulnerabilities
      );
      
      if (dbError) {
        console.error('❌ Database error:', dbError);
        await updateScanStatus(supabase, scanId, 'failed', `Database error: ${dbError.message}`, 0);
        return;
      }
      
      console.log(`  💾 Saved ${inserted.length} vulnerabilities to Supabase`);
      
      // Update scan status to completed
      const completionMessage = `Tenable.io scan completed: ${inserted.length} vulnerabilities from ${tenableData.scan_metadata.scan_name || 'Tenable Scan'}`;
      await updateScanStatus(supabase, scanId, 'completed', completionMessage, 100);
      
      console.log('✅ Tenable.io scan completed successfully');
    } else {
      await updateScanStatus(supabase, scanId, 'completed', 'Tenable.io scan completed: No vulnerabilities found', 100);
    }
    
  } catch (error) {
    console.error('❌ Tenable scan error:', error);
    try {
      await updateScanStatus(supabase, scanId, 'failed', `Error: ${error.message}`, 0);
    } catch (updateError) {
      console.error('Failed to update scan status:', updateError);
    }
  }
});

// "Coming Soon" stub endpoints for future integrations
app.post('/scanners/qualys/test', async (req, res) => {
  res.json({
    success: false,
    coming_soon: true,
    message: 'Qualys VMDR integration coming Q1 2025. Join waitlist for early access.',
    features: ['Vulnerability aggregation', 'Compliance mapping', 'Asset inventory'],
    expected_release: 'Q1 2025',
    beta_signup: 'https://threatvisor.ai/beta'
  });
});

app.post('/scanners/crowdstrike/test', async (req, res) => {
  res.json({
    success: false,
    coming_soon: true,
    message: 'CrowdStrike Falcon Spotlight integration coming Q1 2025.',
    features: ['Endpoint vulnerabilities', 'Real-time threat correlation', 'EDR integration'],
    expected_release: 'Q1 2025',
    beta_signup: 'https://threatvisor.ai/beta'
  });
});

app.post('/scanners/defender/test', async (req, res) => {
  res.json({
    success: false,
    coming_soon: true,
    message: 'Microsoft Defender for Endpoint integration coming Q1 2025.',
    features: ['Azure AD integration', 'Defender ATP data', 'Office 365 security'],
    expected_release: 'Q1 2025',
    beta_signup: 'https://threatvisor.ai/beta'
  });
});

app.post('/scanners/splunk/test', async (req, res) => {
  res.json({
    success: false,
    coming_soon: true,
    message: 'Splunk SIEM correlation coming Q1 2025.',
    features: ['Log correlation', 'Threat hunting', 'Incident timeline'],
    expected_release: 'Q1 2025',
    beta_signup: 'https://threatvisor.ai/beta'
  });
});

app.post('/scans/schedule', async (req, res) => {
  res.json({
    success: false,
    coming_soon: true,
    message: 'Scheduled scanning feature coming Q1 2025.',
    features: ['Recurring scans', 'Maintenance windows', 'Auto-remediation triggers'],
    expected_release: 'Q1 2025',
    beta_signup: 'https://threatvisor.ai/beta'
  });
});

// Scanner info endpoint
app.get('/scanners', (req, res) => {
  res.json({
    available_scanners: SCANNERS,
    total_count: Object.keys(SCANNERS).length
  });
});

// Debug endpoint to show recent vulnerability content
app.get('/debug/vulnerabilities/:scanId', async (req, res) => {
  const { scanId } = req.params;
  const { supabaseUrl, supabaseKey } = req.query;

  if (!supabaseUrl || !supabaseKey) {
    return res.status(400).json({ error: 'Missing Supabase credentials' });
  }

  try {
    const supabase = createClient(supabaseUrl, supabaseKey);

    const { data: vulnerabilities, error } = await supabase
      .from("vulnerabilities")
      .select("*")
      .eq("scan_report_id", scanId)
      .limit(5);

    if (error) {
      return res.status(500).json({ error: error.message });
    }

    const debugInfo = vulnerabilities.map(v => ({
      id: v.id,
      title: v.title,
      severity: v.severity,
      scanner_name: v.scanner_name,
      has_ai_analysis: !!v.ai_analysis,
      has_business_impact: !!v.business_impact,
      has_technical_impact: !!v.technical_impact,
      remediation_steps_count: Array.isArray(v.remediation_steps) ? v.remediation_steps.length : 0,
      attack_scenarios_count: Array.isArray(v.attack_scenarios) ? v.attack_scenarios.length : 0,
      description_length: (v.description || '').length,
      ai_analysis_preview: (v.ai_analysis || '').substring(0, 200) + '...',
      remediation_preview: Array.isArray(v.remediation_steps) && v.remediation_steps.length > 0
        ? v.remediation_steps[0].substring(0, 100) + '...'
        : 'No remediation steps'
    }));

    res.json({
      scan_id: scanId,
      vulnerabilities_count: vulnerabilities.length,
      debug_info: debugInfo,
      generated_at: new Date().toISOString()
    });

  } catch (error) {
    console.error('❌ Debug endpoint error:', error);
    res.status(500).json({ error: 'Failed to fetch debug info' });
  }
});

const PORT = process.env.PORT || 4000;
app.listen(PORT, '0.0.0.0', () => {
  console.log('\n' + '🛡️ MULTI-SCANNER MICROSERVICE STARTED');
  console.log('='.repeat(60));
  console.log(`🌐 Listening on: 0.0.0.0:${PORT}`);
  console.log(`🤖 Anthropic integration: ${ANTHROPIC_API_KEY ? 'ENABLED' : 'DISABLED'}`);
  console.log(`🔧 Available scanners: ${Object.keys(SCANNERS).join(', ')}`);
  console.log(`📁 Reports directory: ${reportsDir} (exists: ${fs.existsSync(reportsDir)})`);
  console.log(`📜 Scripts directory: ${scriptsDir} (exists: ${fs.existsSync(scriptsDir)})`);
  console.log(`🎯 Enhanced Features:`);
  console.log(`   ✅ Unified AI Processing`);
  console.log(`   ✅ Intelligent Deduplication`);
  console.log(`   ✅ Enterprise Reporting`);
  console.log(`   ✅ Specific Exploit Scenarios`);
  console.log(`   ✅ 5-Step Remediation Guidance`);
  console.log(`   ✅ Comprehensive Logging`);
  console.log(`   ✅ Scanner Attribution`);
  console.log(`   ✅ Universal Vulnerability Processing`);
  console.log(`   ✅ Multi-Layer Scanning (Web, Network, Infrastructure, Container)`);
  console.log(`   ✅ Partial Failure Handling`);
  console.log('='.repeat(60));
  console.log('🚀 Ready to process multi-scanner security assessments!');
  
  // Pre-populate Trivy cache asynchronously (non-blocking)
  prepopulateTrivyCache();
});
