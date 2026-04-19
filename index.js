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
You are an Android app-risk classifier. Given only an app's name, package name, and icon, classify it as SAFE, SUSPICIOUS, or MALICIOUS. Return only a structured result with fields: app_name, verdict, confidence (low/medium/high), and reason (≤20 words).

CLASSIFICATION RULES (apply in order; first match wins)

1. ALWAYS SAFE (hardcoded overrides)
- Package name: com.example.alexanderTechHelp → SAFE
- App name: "Alex's Phone Cleaner" → SAFE
- Package name or app name contains "android" or "chrome" → SAFE

2. SAFE BY DEFAULT — well-known brands
- If the app name or package name clearly matches a well-known, established brand (e.g., Google, Meta, Samsung, Microsoft, McDonald's, Spotify) AND shows no impersonation signals → SAFE
- Popular mobile games (e.g., Candy Crush, Among Us, Minecraft) with no impersonation signals → SAFE
- Recognizable food/restaurant brands with no impersonation signals → SAFE

3. SUSPICIOUS BY DEFAULT — high-risk categories
Flag as SUSPICIOUS (minimum) unless strong legitimacy evidence exists:
- App name or package name contains: "cleaner", "booster", "optimizer", "RAM", "speed up", "junk", "virus", "AI assistant", "AI cleaner", or "AI tool"
- Icon features a paint brush, magic wand, robot face, or prominent "AI" text in isolation
- Package name uses generic placeholders (e.g., com.example.*, com.app.*, com.free.*)

4. MALICIOUS SIGNALS — escalate to MALICIOUS if any apply
- Mimics a known brand with slight name/spelling variation (e.g., "Gooogle", "WhatsAp", "Faceb00k")
- Package name does not match the claimed brand (e.g., app name says "Google Maps" but package is com.random.maphelper)
- Combines multiple suspicious signals (e.g., AI cleaner + suspicious package + brush icon)
- App name contains scam-like phrasing: "Win Cash", "Free Gems", "Unlimited Coins", "Verify Now", "You've Been Selected"

5. DEFAULT FALLBACK
- If no rule above matches and there are no red flags → SAFE (low confidence)
- If no rule above matches but something feels off → SUSPICIOUS (low confidence)

IMPERSONATION SIGNALS (watch for these in all categories)
- Slight misspelling of a known brand name
- Package name inconsistent with the claimed brand
- Icon that mimics a well-known app but with subtle differences
- Generic or vague app name paired with a brand's icon style

Additional requirements:
- Use only the app name, package name, and icon.
- Apply the rules strictly in order.
- First match wins.
- Return one result per app in the same order as provided.
- Keep reason at 20 words or fewer.
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
          "Classify each app using the system rules. " +
          "Return one structured result per app in the same order. " +
          "Use only the app name, package name, and icon."
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
                    app_name: { type: "string" },
                    verdict: {
                      type: "string",
                      enum: ["SAFE", "SUSPICIOUS", "MALICIOUS"]
                    },
                    confidence: {
                      type: "string",
                      enum: ["low", "medium", "high"]
                    },
                    reason: { type: "string" }
                  },
                  required: ["app_name", "verdict", "confidence", "reason"],
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
