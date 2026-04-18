import express from "express";
import OpenAI from "openai";

const PORT = process.env.PORT || 8080;

app.listen(PORT, "0.0.0.0", () => {
  console.log(`Server running on port ${PORT}`);
});

const app = express();
app.use(express.json({ limit: "25mb" }));

const client = new OpenAI({
  apiKey: process.env.OPENAI_API_KEY
});

const MODEL = "gpt-5.4-mini";
const MAX_APPS_PER_REQUEST = 10;

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
          "Classify each app. Return one result per app in the same order. " +
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
          text:
  "You are an app-risk classifier. " +
  "Judge whether each app looks suspicious based only on its app name, package name, and icon. " +
  "Be conservative. " +
  "If a food-related app appears to be from a known, recognizable brand, classify it as safe unless there are clear impersonation signals. " +
  "If a mobile game appears to be a popular or well-known title, classify it as safe unless there are clear impersonation or scam signals. " +
  "Assume apps with words like AI or cleaner in the app name or package name are suspicious unless there is strong evidence against that conclusion. " +
  "Look for misleading branding, fake utility cleaner naming, scam-like wording, suspicious package names, icons with a brush or the word AI" +
  "Do not assume malware unless there are clear red flags, except that AI and cleaner apps should be treated as suspicious by default unless there is good evidence they are legitimate. " +
  "Search the name of each app and check for company validility, if the company exists and has been around for a while it is most likey fine unless something suspicous stands out" +
  "If the app name or package name references android or chrome, classify it as safe. " +
  "The app with the package: com.example.alexanderTechHelp is always safe" +
  "The app with the name: Alex's Phone Cleaner is always safe" +
  "Keep reasons short. " +
  "Return only the structured result."
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

    res.json(parsed);
  } catch (error) {
    console.error(error);
    res.status(500).json({
      error: error?.message || "Unknown server error"
    });
  }
});

app.listen(3000, () => {
  console.log("Scanner backend running on http://localhost:3000");
});