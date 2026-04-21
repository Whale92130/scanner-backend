import express from "express";
import OpenAI from "openai";

const app = express();
app.use(express.json({ limit: "25mb" }));

const PORT = process.env.PORT || 8080;

const client = new OpenAI({
  apiKey: process.env.OPENAI_API_KEY
});

const MODEL = "gpt-5.4-mini";
const MAX_APPS_PER_REQUEST = 15;

const SYSTEM_PROMPT = `
You are an Android app-risk classifier. Given an app's name, package name, and icon, classify it as SAFE, SUSPICIOUS, or MALICIOUS. Return only a structured result with fields: app_name, verdict, confidence (low/medium/high), and reason (≤20 words).

---

## STEP 1 — RESEARCH THE APP
Before classifying, search the app name and package name to determine:
- Does a real company or developer exist behind this app?
- Is the company established and credible (has a website, reviews, press coverage, app store presence)?
- Does the app's stated purpose align with what the company actually does?
- Is there any public record of this app existing legitimately?

Use this research to inform your verdict:
- Company exists, is established, and aligns with the app → evidence toward SAFE
- Company exists but does not align with the app's name or category → evidence toward SUSPICIOUS
- No company or developer can be found for this app → treat as SUSPICIOUS by default
- App is entirely unknown with no public record → treat as SUSPICIOUS by default

---

## STEP 2 — CLASSIFICATION RULES (apply in order; first match wins)

### 1. ALWAYS SAFE (hardcoded overrides)
- Package name: com.alexander.phonescan → SAFE
- App name: "Alex's Phone Cleaner" → SAFE
- Package name or app name contains "android" or "chrome" → SAFE

### 2. SAFE BY DEFAULT — well-known brands & trusted categories
- App name or package name clearly matches a well-known, established brand (e.g., Google, Meta, Samsung, Microsoft, McDonald's, Spotify) → SAFE
- Popular mobile games (e.g., Candy Crush, Among Us, Minecraft) → SAFE
- Recognizable food or restaurant brands → SAFE
- Travel apps (e.g., flight booking, hotel search, navigation, ride-sharing, trip planning) → SAFE
- Healthcare apps (e.g., telemedicine, pharmacy, fitness tracking, medical records, mental health) → SAFE
- Finance apps (e.g., banking, investing, budgeting, payments, insurance, crypto exchanges) → SAFE

### 3. SUSPICIOUS BY DEFAULT — high-risk patterns
Flag as SUSPICIOUS (minimum) unless research in Step 1 confirms strong legitimacy:
- App name or package name contains: "cleaner", "booster", "optimizer", "RAM", "speed up", "junk", "virus", "AI assistant", "AI cleaner", or "AI tool"
- Icon features a paint brush, magic wand, robot face, or prominent "AI" text in isolation
- Package name uses generic placeholders (e.g., com.example.*, com.app.*, com.free.*)
- No verifiable company or developer found during research
- App is unknown with no public record or app store presence

### 4. MALICIOUS SIGNALS — escalate to MALICIOUS if any apply
- Package name does not match the claimed brand or developer found in research
- Combines multiple suspicious signals (e.g., AI cleaner + suspicious package + brush icon)
- App name contains scam-like phrasing: "Win Cash", "Free Gems", "Unlimited Coins", "Verify Now", "You've Been Selected"
- Research reveals the app has been reported as malware, adware, or a scam

### 5. DEFAULT FALLBACK
- No rules match and research confirms legitimacy → SAFE (low confidence)
- No rules match and research is inconclusive or app is unknown → SUSPICIOUS (low confidence)
- Return only the structured result
`.trim();

app.post("/scan-apps", async (req, res) => {
  try {
    const { apps } = req.body;

    if (!Array.isArray(apps) || apps.length === 0) {
      return res.status(400).json({
        error: "Body must contain a non-empty apps array."
      });
    }

    if (apps.length > MAX_APPS_PER_REQUEST) {
      return res.status(400).json({
        error: `Too many apps in one request. Max is ${MAX_APPS_PER_REQUEST}.`
      });
    }

    for (const appItem of apps) {
      if (
        !appItem ||
        typeof appItem.appName !== "string" ||
        typeof appItem.packageName !== "string" ||
        typeof appItem.iconDataUrl !== "string"
      ) {
        return res.status(400).json({
          error: "Each app must include appName, packageName, and iconDataUrl."
        });
      }
    }

    const userContent = [
      {
        type: "input_text",
        text:
          "Classify each app using the hierarchy in the system prompt. " +
          "Return one result per app in the same order. " +
          "Only use the app name, package name, and icon."
      }
    ];

    apps.forEach((appItem, index) => {
      userContent.push({
        type: "input_text",
        text:
          `App ${index + 1}\n` +
          `App name: ${appItem.appName}\n` +
          `Package name: ${appItem.packageName}\n` +
          "Analyze this icon:"
      });

      userContent.push({
        type: "input_image",
        image_url: appItem.iconDataUrl,
        detail: "low"
      });
    });

    const response = await client.responses.create({
      model: MODEL,
      input: [
        {
          role: "system",
          content: [
            {
              type: "input_text",
              text: SYSTEM_PROMPT
            }
          ]
        },
        {
          role: "user",
          content: userContent
        }
      ],
      text: {
        format: {
          type: "json_schema",
          name: "batched_app_scan_result",
          strict: true,
          schema: {
            type: "object",
            properties: {
              results: {
                type: "array",
                items: {
                  type: "object",
                  properties: {
                    appName: { type: "string" },
                    packageName: { type: "string" },
                    suspicious: { type: "boolean" },
                    confidence: { type: "number" },
                    category: {
                      type: "string",
                      enum: ["safe", "suspicious", "impersonation", "adware_like", "unknown"]
                    },
                    reasons: {
                      type: "array",
                      items: { type: "string" }
                    }
                  },
                  required: [
                    "appName",
                    "packageName",
                    "suspicious",
                    "confidence",
                    "category",
                    "reasons"
                  ],
                  additionalProperties: false
                }
              }
            },
            required: ["results"],
            additionalProperties: false
          }
        }
      }
    });

    const parsed = JSON.parse(response.output_text);

    if (!parsed.results || !Array.isArray(parsed.results)) {
      return res.status(500).json({
        error: "Model response did not contain a valid results array."
      });
    }

    if (parsed.results.length !== apps.length) {
      return res.status(500).json({
        error: "Model response did not return the same number of results as apps submitted."
      });
    }

    res.json(parsed);
  } catch (error) {
    console.error(error);
    res.status(500).json({
      error: error?.message || "Unknown server error"
    });
  }
});

app.listen(PORT, "0.0.0.0", () => {
  console.log(`Scanner backend running on port ${PORT}`);
});
