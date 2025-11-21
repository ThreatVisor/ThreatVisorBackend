import Anthropic from '@anthropic-ai/sdk';

const ANTHROPIC_API_KEY = process.env.ANTHROPIC_API_KEY;
const ANTHROPIC_MODEL = process.env.ANTHROPIC_MODEL || "claude-sonnet-4-5-20250929";

async function testAnthropicEnterprise() {
    if (!ANTHROPIC_API_KEY) {
        console.error("❌ ANTHROPIC_API_KEY is not set.");
        process.exit(1);
    }

    console.log(`🔑 Using Anthropic model: ${ANTHROPIC_MODEL}`);

    const anthropic = new Anthropic({
        apiKey: ANTHROPIC_API_KEY,
    });

    const companyProfile = {
        company_name: "Acme Healthcare",
        industry: "Healthcare",
        compliance_requirements: ["HIPAA", "SOC2"]
    };

    const businessContext = `
**BUSINESS CONTEXT:**
- Company: ${companyProfile.company_name}
- Industry: ${companyProfile.industry}
- Compliance: ${companyProfile.compliance_requirements.join(', ')}
`;

    const prompt = `You are a senior cybersecurity analyst.
${businessContext}

Analyze a "Missing HSTS Header" vulnerability.
Provide:
1. CVSS v3.1 Vector
2. False Positive Likelihood (Low/Medium/High)
3. Specific Compliance Controls (HIPAA/SOC2)

Return JSON format as specified in the main application prompt.
`;

    try {
        const msg = await anthropic.messages.create({
            model: ANTHROPIC_MODEL,
            max_tokens: 1000,
            temperature: 0.3,
            system: "You are a helpful assistant. Return ONLY valid JSON.",
            messages: [
                {
                    role: "user",
                    content: prompt
                }
            ]
        });

        console.log("✅ Response received:");
        console.log(msg.content[0].text);
    } catch (error) {
        console.error("❌ Error calling Anthropic API:", error);
    }
}

testAnthropicEnterprise();
