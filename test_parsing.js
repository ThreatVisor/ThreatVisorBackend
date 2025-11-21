
const mockResponses = [
    // 1. Clean JSON
    `{
    "summary": { "total": 1 },
    "vulnerabilities": []
  }`,

    // 2. Markdown code block
    `Here is the analysis:
  \`\`\`json
  {
    "summary": { "total": 1 },
    "vulnerabilities": []
  }
  \`\`\``,

    // 3. Conversational text
    `Sure, here is the JSON:
  {
    "summary": { "total": 1 },
    "vulnerabilities": []
  }
  Hope this helps!`,

    // 4. The problematic one (simulated based on logs)
    `\`\`\`json
  {
    "summary": {
      "total_unique_vulnerabilities": 25,
      "duplicates_merged": 0,
      "overall_risk_assessment": "CRITICAL - The pranascience.com WordPress application exhibits severe security deficiencies..."
    },
    "vulnerabilities": []
  }
  \`\`\``
];

function cleanAndParse(aiResponse) {
    console.log('--- Testing Response ---');
    // console.log('Original:', aiResponse);

    let cleaned = aiResponse;

    // CURRENT LOGIC (Simulated)
    if (cleaned.includes('```json')) {
        cleaned = cleaned.replace(/```json\n?|\n?```/g, '').trim();
    } else if (cleaned.includes('```')) {
        cleaned = cleaned.replace(/```\n?|\n?```/g, '').trim();
    }

    try {
        JSON.parse(cleaned);
        console.log('✅ Current Logic: Success');
    } catch (e) {
        console.log('❌ Current Logic: Failed', e.message);
    }

    // PROPOSED LOGIC
    try {
        const start = aiResponse.indexOf('{');
        const end = aiResponse.lastIndexOf('}');

        if (start === -1 || end === -1) {
            throw new Error('No JSON object found');
        }

        const extracted = aiResponse.substring(start, end + 1);
        JSON.parse(extracted);
        console.log('✅ Proposed Logic: Success');
    } catch (e) {
        console.log('❌ Proposed Logic: Failed', e.message);
    }
}

mockResponses.forEach(cleanAndParse);
