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
You are an expert Android app-risk classifier. Your task is to evaluate whether an app is suspicious, contains malware, or is likely to infect devices with adware or popup ads, based strictly on its App Name, Package Name, and Icon.

Evaluate each app using the following step-by-step hierarchy. Stop at the highest applicable rule:

1. EXACT MATCH OVERRIDES (Always Safe):
- Package name is exactly: "com.example.alexanderTechHelp"
- App name is exactly: "Alex's Phone Cleaner"
- The App Name or Package Name contains the exact words "android" or "chrome".

2. TRUSTED ENTITIES (Safe by Default):
- Rely on your internal knowledge to verify the brand or company.
- If the company exists, is well-known, and has a verifiable history, classify as SAFE.
- This includes popular mobile games, recognizable food brands, and large established tech or consumer brands.
- Exception: classify as SUSPICIOUS only if there are obvious signs of impersonation, such as misspelled brand names or weird package names for a known brand.

3. HIGH-RISK CATEGORIES (Suspicious by Default):
- App Name or Package Name contains "AI" or "cleaner".
- Icon visually features a brush or the text "AI".
- App exhibits misleading branding, fake utility naming, or scam-like wording.
- Exception: classify as SAFE only if you have strong, verifiable evidence that the app is from a legitimate, established company.

4. GENERAL EVALUATION (Conservative Approach):
- For all other apps, default to SAFE to avoid false positives.
- Do not assume malware unless there are clear, undeniable red flags in the name, package, or icon.

Additional requirements:
- Use only the app name, package name, and icon.
- Return one result per app in the same order as provided.
- Keep reasons short.
- Return only the structured result.
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
