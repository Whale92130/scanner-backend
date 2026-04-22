import express from "express";
import OpenAI from "openai";
import { initializeApp, applicationDefault } from "firebase-admin/app";
import { getFirestore, FieldValue } from "firebase-admin/firestore";

const app = express();
app.use(express.json({ limit: "25mb" }));

const PORT = process.env.PORT || 8080;

const client = new OpenAI({
  apiKey: process.env.OPENAI_API_KEY
});

initializeApp({
  credential: applicationDefault()
});

const db = getFirestore();

const MODEL = "gpt-5.4-mini";
const MAX_APPS_PER_REQUEST = 15;

const VALID_CATEGORIES = new Set([
  "safe",
  "suspicious",
  "impersonation",
  "adware_like",
  "unknown"
]);

const SYSTEM_PROMPT = `
You are an Android app-risk classifier. Given only an app's name, package name, and icon, classify it using the ordered rules below. First match wins.

1. ALWAYS SAFE (hardcoded overrides)
- Package name exactly "com.example.alexanderTechHelp" -> SAFE
- App name exactly "Alex's Phone Cleaner" -> SAFE
- If the package name or app name contains "android" or "chrome" -> SAFE

2. SAFE BY DEFAULT — well-known brands
- If the app name or package name clearly matches a well-known, established brand and shows no impersonation signals -> SAFE
- Popular mobile games with no impersonation signals -> SAFE
- Recognizable food or restaurant brands with no impersonation signals -> SAFE

3. SUSPICIOUS BY DEFAULT — high-risk categories
Classify as suspicious at minimum unless strong legitimacy evidence exists:
- App name or package name contains "cleaner", "booster", "optimizer", "RAM", "speed up", "junk", "virus", "AI assistant", "AI cleaner", or "AI tool"
- Icon features a paint brush, magic wand, robot face, or prominent "AI" text in isolation
- Package name uses generic placeholders such as "com.example.*", "com.app.*", or "com.free.*"

4. MALICIOUS SIGNALS — escalate to the strongest suspicious judgment if any apply
- Mimics a known brand with a slight name or spelling variation
- Package name does not match the claimed brand
- Combines multiple suspicious signals
- App name contains scam-like phrasing such as "Win Cash", "Free Gems", "Unlimited Coins", "Verify Now", or "You've Been Selected"

5. DEFAULT FALLBACK
- If no rule above matches and there are no red flags -> SAFE with lower confidence
- If no rule above matches but something still feels off -> SUSPICIOUS with lower confidence

Impersonation signals include:
- Slight misspelling of a known brand name
- Package name inconsistent with the claimed brand
- Icon that mimics a well-known app with subtle differences
- Generic or vague app name paired with a brand-like icon style

Additional requirements:
- Use only the app name, package name, and icon
- Return one result per app in the same order as provided
- Keep reasons short
- Keep using the existing output schema exactly
- Map SAFE to suspicious=false and category="safe"
- Map suspicious judgments to suspicious=true and category="suspicious", "adware_like", "impersonation", or "unknown" as appropriate
- If the app looks like a fake or copy of a known brand, use category="impersonation"
- Confidence must remain a number between 0 and 1
- Return only the structured result
`.trim();

function normalizeString(value) {
  return typeof value === "string" ? value.trim() : "";
}

function inferFeedbackDecision(body) {
  let suspicious;
  let category;

  if (typeof body.suspicious === "boolean") {
    suspicious = body.suspicious;
  } else if (typeof body.isGood === "boolean") {
    suspicious = !body.isGood;
  } else if (typeof body.finalLabel === "string") {
    const label = body.finalLabel.trim().toLowerCase();

    if (["safe", "good", "allow", "trusted", "benign"].includes(label)) {
      suspicious = false;
    } else if (
      ["bad", "harmful", "suspicious", "malicious", "adware_like", "impersonation", "unknown"].includes(label)
    ) {
      suspicious = true;
    }
  }

  if (typeof suspicious !== "boolean") {
    return null;
  }

  if (typeof body.category === "string" && VALID_CATEGORIES.has(body.category)) {
    category = body.category;
  } else {
    category = suspicious ? "suspicious" : "safe";
  }

  return { suspicious, category };
}

function feedbackDocToResponse(doc) {
  if (!doc || !doc.exists) return null;
  const data = doc.data();

  return {
    appName: data.appName,
    packageName: data.packageName,
    suspicious: Boolean(data.suspicious),
    category: VALID_CATEGORIES.has(data.category) ? data.category : (data.suspicious ? "suspicious" : "safe"),
    notes: Array.isArray(data.notes) ? data.notes : [],
    source: data.source || "feedback_db",
    updatedAt: data.updatedAt ?? null,
    lastUserDecision: data.lastUserDecision ?? null
  };
}

function feedbackToScanResult(appItem, feedback) {
  return {
    appName: appItem.appName,
    packageName: appItem.packageName,
    suspicious: Boolean(feedback.suspicious),
    confidence: 0.99,
    category: VALID_CATEGORIES.has(feedback.category)
      ? feedback.category
      : (feedback.suspicious ? "suspicious" : "safe"),
    reasons: feedback.suspicious
      ? ["Stored harmful-app feedback"]
      : ["Stored safe-app feedback"]
  };
}

async function loadFeedbackMapByPackages(packageNames) {
  if (!Array.isArray(packageNames) || packageNames.length === 0) {
    return {};
  }

  const uniquePackageNames = [...new Set(packageNames.map(normalizeString).filter(Boolean))];
  if (uniquePackageNames.length === 0) {
    return {};
  }

  const refs = uniquePackageNames.map((pkg) => db.collection("app_feedback").doc(pkg));
  const snapshots = await Promise.all(refs.map((ref) => ref.get()));

  const map = {};
  for (const snap of snapshots) {
    if (snap.exists) {
      map[snap.id] = snap.data();
    }
  }
  return map;
}

async function classifyAppsWithModel(apps) {
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
    throw new Error("Model response did not contain a valid results array.");
  }

  if (parsed.results.length !== apps.length) {
    throw new Error("Model response did not return the same number of results as apps submitted.");
  }

  return parsed.results;
}

app.get("/health", async (_req, res) => {
  res.json({
    ok: true,
    model: MODEL,
    firestore: true
  });
});

app.post("/feedback", async (req, res) => {
  try {
    const appName = normalizeString(req.body.appName);
    const packageName = normalizeString(req.body.packageName);
    const notes = Array.isArray(req.body.notes)
      ? req.body.notes.map(normalizeString).filter(Boolean)
      : [];
    const userDecision = normalizeString(req.body.userDecision) || null;

    if (!appName || !packageName) {
      return res.status(400).json({
        error: "appName and packageName are required."
      });
    }

    const parsedDecision = inferFeedbackDecision(req.body);
    if (!parsedDecision) {
      return res.status(400).json({
        error:
          "Provide one of: suspicious(boolean), isGood(boolean), or finalLabel(string)."
      });
    }

    const payload = {
      appName,
      packageName,
      suspicious: parsedDecision.suspicious,
      category: parsedDecision.category,
      notes,
      source: "user_feedback",
      lastUserDecision: userDecision,
      updatedAt: FieldValue.serverTimestamp()
    };

    await db.collection("app_feedback").doc(packageName).set(payload, { merge: true });

    await db.collection("feedback_events").add({
      ...payload,
      createdAt: FieldValue.serverTimestamp()
    });

    res.json({
      ok: true,
      saved: {
        appName,
        packageName,
        suspicious: parsedDecision.suspicious,
        category: parsedDecision.category
      }
    });
  } catch (error) {
    console.error("POST /feedback failed:", error);
    res.status(500).json({
      error: error?.message || "Failed to save feedback."
    });
  }
});

app.get("/feedback/:packageName", async (req, res) => {
  try {
    const packageName = normalizeString(req.params.packageName);

    if (!packageName) {
      return res.status(400).json({
        error: "packageName is required."
      });
    }

    const doc = await db.collection("app_feedback").doc(packageName).get();
    const feedback = feedbackDocToResponse(doc);

    if (!feedback) {
      return res.status(404).json({
        found: false
      });
    }

    res.json({
      found: true,
      feedback
    });
  } catch (error) {
    console.error("GET /feedback/:packageName failed:", error);
    res.status(500).json({
      error: error?.message || "Failed to load feedback."
    });
  }
});

app.post("/feedback/batch-lookup", async (req, res) => {
  try {
    const packageNames = Array.isArray(req.body.packageNames)
      ? req.body.packageNames.map(normalizeString).filter(Boolean)
      : [];

    if (packageNames.length === 0) {
      return res.status(400).json({
        error: "Body must contain a non-empty packageNames array."
      });
    }

    const feedbackMap = await loadFeedbackMapByPackages(packageNames);

    res.json({
      feedback: feedbackMap
    });
  } catch (error) {
    console.error("POST /feedback/batch-lookup failed:", error);
    res.status(500).json({
      error: error?.message || "Failed to load feedback batch."
    });
  }
});

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

    let feedbackMap = {};
    try {
      feedbackMap = await loadFeedbackMapByPackages(apps.map((a) => a.packageName));
    } catch (feedbackError) {
      console.error("Feedback lookup failed, continuing without overrides:", feedbackError);
    }

    const finalResults = new Array(apps.length);
    const appsForModel = [];
    const appsForModelOriginalIndexes = [];

    apps.forEach((appItem, index) => {
      const feedback = feedbackMap[appItem.packageName];

      if (feedback) {
        finalResults[index] = feedbackToScanResult(appItem, feedback);
      } else {
        appsForModel.push(appItem);
        appsForModelOriginalIndexes.push(index);
      }
    });

    if (appsForModel.length > 0) {
      const modelResults = await classifyAppsWithModel(appsForModel);

      modelResults.forEach((result, resultIndex) => {
        const originalIndex = appsForModelOriginalIndexes[resultIndex];
        finalResults[originalIndex] = result;
      });
    }

    if (finalResults.some((item) => !item)) {
      return res.status(500).json({
        error: "Server failed to build a complete results array."
      });
    }

    res.json({
      results: finalResults
    });
  } catch (error) {
    console.error("POST /scan-apps failed:", error);
    res.status(500).json({
      error: error?.message || "Unknown server error"
    });
  }
});

app.listen(PORT, "0.0.0.0", () => {
  console.log(`Scanner backend running on port ${PORT}`);
});
