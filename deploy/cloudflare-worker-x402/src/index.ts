/**
 * AttestSeal x402 stamper -- Cloudflare Worker template.
 *
 * Sits in front of your origin. When the origin returns a 402 (or any
 * status in ATTESTSEAL_ONLY_ON_STATUS), the Worker fetches a fresh
 * AttestSeal attestation for ATTESTSEAL_DOMAIN, stamps the X-AttestSeal-*
 * headers on the response, and forwards it to the agent.
 *
 * Cache: the per-domain attestation is cached at the Cloudflare edge with
 * the attestation's expiresAt as the TTL (capped at ATTESTSEAL_CACHE_TTL_SECONDS).
 * One cache miss per Cloudflare PoP per merchant per attestation lifetime;
 * everything else hits the edge.
 *
 * Spec: https://github.com/AttestSeal/attestseal/blob/main/spec/X-ATTESTSEAL-HEADERS.md
 */

export interface Env {
  ATTESTSEAL_DOMAIN: string;
  ATTESTSEAL_API_BASE: string;
  ATTESTSEAL_ONLY_ON_STATUS: string;
  ATTESTSEAL_CACHE_TTL_SECONDS: string;
}

interface Attestation {
  domain: string;
  issuer: string;
  checkedAt: string;
  expiresAt: string;
  trustScore: number;
  recommendation: string;
  confidence: string;
  cautionReason: string | null;
  assuranceBasis: string;
  agentPolicyHint: string | null;
  scoringModel: string;
  siteCategory: string | null;
  parentCompany: string | null;
  parentFloorInherited: boolean;
  signature: string;
  signatureKeyId: string;
}

const SPEC_VERSION = '0.1.0';

export default {
  async fetch(request: Request, env: Env, ctx: ExecutionContext): Promise<Response> {
    const onlyOnStatus = (env.ATTESTSEAL_ONLY_ON_STATUS || '402')
      .split(',').map((s) => parseInt(s.trim(), 10)).filter((n) => !isNaN(n));

    // Forward to origin first; we stamp on the way back.
    const originResponse = await fetch(request);

    if (!onlyOnStatus.includes(originResponse.status)) {
      return originResponse;
    }

    const attestation = await getAttestation(env, ctx);
    if (!attestation) {
      // Origin response is fine even without stamping; agent will fall back
      // to direct API call. Don't fail closed at the cost of a partner
      // outage.
      return originResponse;
    }

    const stamped = new Response(originResponse.body, {
      status: originResponse.status,
      statusText: originResponse.statusText,
      headers: originResponse.headers,
    });
    stampHeaders(stamped, attestation);
    return stamped;
  },
};


async function getAttestation(env: Env, ctx: ExecutionContext): Promise<Attestation | null> {
  const cacheKey = new Request(
    `https://attestseal-cache.invalid/v1/check/${env.ATTESTSEAL_DOMAIN}`,
    { method: 'GET' },
  );
  const cache = caches.default;

  const cached = await cache.match(cacheKey);
  if (cached) {
    try {
      return await cached.json<Attestation>();
    } catch {
      // Fall through to refetch on parse error
    }
  }

  const apiBase = env.ATTESTSEAL_API_BASE || 'https://api.attestseal.com';
  const url = `${apiBase}/v1/check/${env.ATTESTSEAL_DOMAIN}`;
  const upstream = await fetch(url, { cf: { cacheEverything: false } });
  if (!upstream.ok) {
    return null;
  }

  const attestation: Attestation = await upstream.json();

  // Compute cache TTL: smaller of (configured) and (expiresAt - now).
  const configuredTtl = parseInt(env.ATTESTSEAL_CACHE_TTL_SECONDS || '86400', 10);
  const expiresAtMs = Date.parse(attestation.expiresAt);
  const ttlFromExpiry = isNaN(expiresAtMs) ? configuredTtl : Math.max(0, Math.floor((expiresAtMs - Date.now()) / 1000));
  const ttl = Math.min(configuredTtl, ttlFromExpiry);

  const cachePut = new Response(JSON.stringify(attestation), {
    headers: {
      'content-type': 'application/json',
      'cache-control': `public, max-age=${ttl}`,
    },
  });
  ctx.waitUntil(cache.put(cacheKey, cachePut));
  return attestation;
}


function stampHeaders(response: Response, a: Attestation): void {
  response.headers.set('X-AttestSeal-Issuer', a.issuer);
  response.headers.set('X-AttestSeal-Domain', a.domain);
  response.headers.set('X-AttestSeal-Score', String(a.trustScore));
  response.headers.set('X-AttestSeal-Recommendation', a.recommendation);
  response.headers.set('X-AttestSeal-Confidence', a.confidence);
  response.headers.set('X-AttestSeal-Assurance-Basis', a.assuranceBasis);
  response.headers.set('X-AttestSeal-Issued-At', a.checkedAt);
  response.headers.set('X-AttestSeal-Expires-At', a.expiresAt);
  response.headers.set('X-AttestSeal-Scoring-Model', a.scoringModel);
  response.headers.set('X-AttestSeal-Signature', a.signature);
  response.headers.set('X-AttestSeal-Key-Id', a.signatureKeyId);
  response.headers.set('X-AttestSeal-Parent-Floor-Inherited', a.parentFloorInherited ? 'true' : 'false');
  response.headers.set('X-AttestSeal-Spec-Version', SPEC_VERSION);

  if (a.cautionReason) response.headers.set('X-AttestSeal-Caution-Reason', a.cautionReason);
  if (a.siteCategory) response.headers.set('X-AttestSeal-Site-Category', a.siteCategory);
  if (a.parentCompany) response.headers.set('X-AttestSeal-Parent-Company', a.parentCompany);
  if (a.agentPolicyHint) response.headers.set('X-AttestSeal-Agent-Policy-Hint', a.agentPolicyHint);
}
