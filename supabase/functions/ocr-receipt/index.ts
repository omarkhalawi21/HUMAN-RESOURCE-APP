// Supabase Edge Function: ocr-receipt
//
// Receives a base64 receipt image, asks Google Cloud Vision (DOCUMENT_TEXT_DETECTION)
// to read it, and returns the raw text. The browser's parseReceiptText() then
// extracts vendor / date / amount from that text.
//
// Required secret: GOOGLE_VISION_API_KEY (set via Supabase Dashboard →
// Edge Functions → Manage Secrets).

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

Deno.serve(async (req) => {
  if (req.method === "OPTIONS") return new Response("ok", { headers: corsHeaders });
  if (req.method !== "POST") return json({ error: "Method not allowed" }, 405);

  const apiKey = Deno.env.get("GOOGLE_VISION_API_KEY");
  if (!apiKey) return json({ error: "GOOGLE_VISION_API_KEY not configured on the Edge Function" }, 500);

  let payload: { imageBase64?: string; mimeType?: string };
  try {
    payload = await req.json();
  } catch {
    return json({ error: "Invalid JSON body" }, 400);
  }
  const { imageBase64, mimeType } = payload || {};
  if (!imageBase64) return json({ error: "imageBase64 is required" }, 400);
  if (mimeType && !/^image\/(png|jpe?g|webp|gif|bmp|tiff?)$/i.test(mimeType)) {
    return json({ error: `Unsupported mimeType: ${mimeType}` }, 400);
  }

  try {
    const vRes = await fetch(
      `https://vision.googleapis.com/v1/images:annotate?key=${encodeURIComponent(apiKey)}`,
      {
        method: "POST",
        headers: { "Content-Type": "application/json" },
        body: JSON.stringify({
          requests: [
            {
              image: { content: imageBase64 },
              features: [{ type: "DOCUMENT_TEXT_DETECTION" }],
              // Hint at the receipt's languages — Vision will still recognise
              // anything else on the page, but this nudges it on Arabic.
              imageContext: { languageHints: ["en", "ar"] },
            },
          ],
        }),
      }
    );

    if (!vRes.ok) {
      const errText = await vRes.text();
      return json(
        { error: `Vision API error ${vRes.status}: ${errText.slice(0, 500)}` },
        502
      );
    }

    const body = await vRes.json();
    const resp = body?.responses?.[0];
    if (resp?.error) return json({ error: resp.error.message || "Vision API error" }, 502);

    const rawText: string =
      resp?.fullTextAnnotation?.text ||
      resp?.textAnnotations?.[0]?.description ||
      "";

    return json({ raw_text: rawText });
  } catch (e: unknown) {
    const msg = e instanceof Error ? e.message : String(e);
    return json({ error: msg }, 500);
  }
});
