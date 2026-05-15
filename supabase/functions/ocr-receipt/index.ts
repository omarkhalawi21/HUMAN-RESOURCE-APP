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

const EXTRACTION_PROMPT = `You are a receipt OCR engine for a coffee shop's expense tracker. Read the receipt and extract structured fields.

Return ONLY a JSON object, no markdown fences, no commentary, no leading or trailing text:

{
  "vendor": string | null,              // merchant / store / restaurant name
  "merchant_address": string | null,
  "merchant_phone": string | null,
  "merchant_tax_id": string | null,     // VAT number, CR number, GST number, etc
  "country": string | null,             // ISO-2 if you can tell ("SA", "US", "SG"), else null
  "receipt_no": string | null,          // invoice / receipt / order number
  "date": string | null,                // YYYY-MM-DD; convert from any format you see
  "time": string | null,                // HH:MM 24-hour; null if no time on receipt
  "currency": string,                   // 3-letter ISO code; default "SAR" for Arabic receipts, "USD" for $ with no other hint
  "subtotal": number | null,            // pre-tax / pre-VAT total if listed
  "tax": number | null,                 // VAT / GST / sales tax amount if listed
  "amount": number | null,              // the FINAL TOTAL the customer paid (net total / grand total / total due). NEVER subtotal, gross-before-discount, VAT-only, or change-due.
  "payment_method": string | null,      // "cash", "credit_card", "debit_card", "mada", "apple_pay", null if unclear
  "card_type": string | null,           // "visa", "mastercard", "amex", "mada", null
  "line_items": [                       // each purchased item; [] if none readable
    { "qty": number | null, "description": string, "amount": number | null }
  ],
  "raw_text": string                    // every readable line of text on the receipt, joined with \\n
}

Rules:
- The receipt may be bilingual (Arabic + English). Read both. Prefer English names where the receipt is bilingual.
- "amount" is the line clearly labelled "Total" / "Net Total" / "Grand Total" / "Total Due" / "المجموع" — NOT subtotal, NOT gross-before-discount, NOT VAT-only, NOT cash-received-when-a-change-due-is-shown.
- Numbers may use Arabic-Indic digits (٠١٢٣٤٥٦٧٨٩). Convert all to standard ASCII digits.
- Amounts are numbers, not strings: 28.50 not "28.50".
- If a field is genuinely unreadable, use null. Don't guess.
- "line_items" is an array — empty if you can't read individual lines, but include it.
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

    // Coerce numeric fields to numbers when the model handed back strings
    const toNumber = (v: unknown): number | null => {
      if (v == null) return null;
      if (typeof v === "number") return Number.isFinite(v) ? v : null;
      if (typeof v === "string") {
        const n = Number(v.replace(/[^\d.\-]/g, ""));
        return Number.isFinite(n) ? n : null;
      }
      return null;
    };
    const lineItems: Array<{ qty: number | null; description: string; amount: number | null }> =
      Array.isArray(parsed.line_items)
        ? (parsed.line_items as Array<Record<string, unknown>>)
            .map((row) => ({
              qty: toNumber(row?.qty),
              description: typeof row?.description === "string" ? row.description : "",
              amount: toNumber(row?.amount),
            }))
            .filter((row) => row.description || row.amount != null)
        : [];

    return json({
      vendor: typeof parsed.vendor === "string" ? parsed.vendor : null,
      merchant_address: typeof parsed.merchant_address === "string" ? parsed.merchant_address : null,
      merchant_phone: typeof parsed.merchant_phone === "string" ? parsed.merchant_phone : null,
      merchant_tax_id: typeof parsed.merchant_tax_id === "string" ? parsed.merchant_tax_id : null,
      country: typeof parsed.country === "string" ? parsed.country : null,
      receipt_no: typeof parsed.receipt_no === "string" ? parsed.receipt_no : null,
      date: typeof parsed.date === "string" ? parsed.date : null,
      time: typeof parsed.time === "string" ? parsed.time : null,
      currency: typeof parsed.currency === "string" ? parsed.currency : "SAR",
      subtotal: toNumber(parsed.subtotal),
      tax: toNumber(parsed.tax),
      amount: toNumber(parsed.amount),
      payment_method: typeof parsed.payment_method === "string" ? parsed.payment_method : null,
      card_type: typeof parsed.card_type === "string" ? parsed.card_type : null,
      line_items: lineItems,
      raw_text: typeof parsed.raw_text === "string" ? parsed.raw_text : "",
      usage: response.usage,
    });
  } catch (e: unknown) {
    const msg = e instanceof Error ? e.message : String(e);
    return json({ error: msg }, 500);
  }
});
