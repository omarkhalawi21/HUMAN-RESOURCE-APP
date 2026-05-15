// Supabase Edge Function: ocr-receipt
//
// Receives a base64 receipt image, asks Claude Haiku 4.5 Vision to extract
// vendor / date / amount / currency, and returns structured JSON.
//
// Required secret: ANTHROPIC_API_KEY (set via Supabase Dashboard → Edge Functions
// → Manage Secrets, or `supabase secrets set ANTHROPIC_API_KEY=sk-ant-...`).

import Anthropic from "npm:@anthropic-ai/sdk@0.39.0";

const corsHeaders = {
  "Access-Control-Allow-Origin": "*",
  "Access-Control-Allow-Headers": "authorization, x-client-info, apikey, content-type",
  "Access-Control-Allow-Methods": "POST, OPTIONS",
};

const json = (body: unknown, status = 200) =>
  new Response(JSON.stringify(body), {
    status,
    headers: { ...corsHeaders, "Content-Type": "application/json" },
  });

const EXTRACTION_PROMPT = `You are a receipt OCR engine for a coffee shop's expense tracker.

Extract the following fields and return ONLY a JSON object, no markdown fences, no commentary:

{
  "vendor": string | null,        // merchant / store / restaurant name
  "date":   string | null,        // YYYY-MM-DD; convert from any format you see
  "amount": number | null,        // the FINAL TOTAL the customer paid (net total / grand total / total due / cash paid). NEVER subtotal, gross-before-discount, VAT-only, or change-due.
  "currency": string,             // 3-letter ISO code; default "SAR" for Arabic receipts, "USD" for $ with no other hint
  "raw_text": string              // every readable line of text on the receipt, joined with \\n
}

Rules:
- The receipt may be bilingual (Arabic + English). Read both.
- If the receipt shows subtotal, VAT, and total separately, pick the line clearly labelled "Total" / "Net Total" / "Grand Total" / "Total Due" / "المجموع".
- If the receipt shows "Cash Received" or "Paid" and a "Change Due", the AMOUNT is (Cash Received - Change Due), or equivalently the line labelled Total — never the cash-received figure itself if a change-due is present.
- Numbers may use Arabic-Indic digits (٠١٢٣٤٥٦٧٨٩). Convert to standard digits.
- If a field is genuinely unreadable, use null. Don't guess.
- Return ONLY the JSON object, starting with { and ending with }.`;

Deno.serve(async (req) => {
  if (req.method === "OPTIONS") return new Response("ok", { headers: corsHeaders });
  if (req.method !== "POST") return json({ error: "Method not allowed" }, 405);

  const apiKey = Deno.env.get("ANTHROPIC_API_KEY");
  if (!apiKey) return json({ error: "ANTHROPIC_API_KEY not configured on the Edge Function" }, 500);

  let payload: { imageBase64?: string; mimeType?: string };
  try {
    payload = await req.json();
  } catch {
    return json({ error: "Invalid JSON body" }, 400);
  }
  const { imageBase64, mimeType } = payload || {};
  if (!imageBase64 || !mimeType) return json({ error: "imageBase64 and mimeType are required" }, 400);
  if (!/^image\/(png|jpe?g|webp|gif)$/i.test(mimeType)) {
    return json({ error: `Unsupported mimeType: ${mimeType}. Expected image/png|jpeg|webp|gif.` }, 400);
  }

  try {
    const client = new Anthropic({ apiKey });
    const response = await client.messages.create({
      model: "claude-haiku-4-5",
      max_tokens: 2048,
      messages: [
        {
          role: "user",
          content: [
            {
              type: "image",
              source: { type: "base64", media_type: mimeType, data: imageBase64 },
            },
            { type: "text", text: EXTRACTION_PROMPT },
          ],
        },
      ],
    });

    const textBlock = response.content.find((b: { type: string }) => b.type === "text") as
      | { type: "text"; text: string }
      | undefined;
    const raw = (textBlock?.text || "").trim();
    const stripped = raw.replace(/^```(?:json)?\s*/i, "").replace(/```\s*$/i, "").trim();

    let parsed: Record<string, unknown>;
    try {
      parsed = JSON.parse(stripped);
    } catch {
      return json({ error: "Model returned non-JSON", raw }, 502);
    }

    // Coerce amount to a number if the model handed back a string
    if (parsed.amount != null && typeof parsed.amount === "string") {
      const n = Number(String(parsed.amount).replace(/[^\d.\-]/g, ""));
      parsed.amount = Number.isFinite(n) ? n : null;
    }

    return json({
      vendor: parsed.vendor ?? null,
      date: parsed.date ?? null,
      amount: typeof parsed.amount === "number" ? parsed.amount : null,
      currency: typeof parsed.currency === "string" ? parsed.currency : "SAR",
      raw_text: typeof parsed.raw_text === "string" ? parsed.raw_text : "",
      usage: response.usage,
    });
  } catch (e: unknown) {
    const msg = e instanceof Error ? e.message : String(e);
    return json({ error: msg }, 500);
  }
});
