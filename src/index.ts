/**
 * Soukbot async WhatsApp campaign delivery worker.
 *
 *   Odoo  --POST /enqueue (HMAC signed)-->  this worker
 *         batch { phone_number_id, access_token, callback_url, messages[] }
 *   worker --> Cloudflare Queue (one job per recipient)
 *   queue consumer --> Meta Graph POST /{phone_number_id}/messages
 *   worker --POST callback_url (HMAC signed)--> Odoo /whatsapp/campaign/status
 *         results [{ message_id, status:'sent'|'failed', wamid?, error? }]
 *
 * The Meta System User token is sent PER BATCH by Odoo (never stored here),
 * so per-seller tokens in Phase 3 need no worker change. Delivered/read are
 * NOT reported here — they reach Odoo on the Meta status webhook.
 */

interface Env {
	CAMPAIGN_QUEUE: Queue<Job>;
	CAMPAIGN_SECRET: string;
	META_GRAPH_VERSION: string;
}

interface Job {
	phone_number_id: string;
	access_token: string;
	callback_url: string;
	message_id: number;
	to: string;
	template_name: string;
	language: string;
	components: unknown[];
}

interface Result {
	message_id: number;
	status: 'sent' | 'failed';
	wamid?: string;
	error?: string;
}

export default {
	async fetch(req: Request, env: Env): Promise<Response> {
		const url = new URL(req.url);
		if (url.pathname === '/health') return new Response('ok');
		if (req.method !== 'POST' || url.pathname !== '/enqueue') {
			return new Response('Not found', { status: 404 });
		}
		const raw = await req.text();
		const sig = req.headers.get('X-Soukbot-Signature') || '';
		const expected = await hmacHex(env.CAMPAIGN_SECRET, raw);
		if (!env.CAMPAIGN_SECRET || !safeEqual(sig, expected)) {
			return json({ error: 'bad signature' }, 403);
		}
		let batch: any;
		try {
			batch = JSON.parse(raw);
		} catch {
			return json({ error: 'bad json' }, 400);
		}
		const { phone_number_id, access_token, callback_url, messages } = batch;
		if (!phone_number_id || !access_token || !callback_url || !Array.isArray(messages)) {
			return json({ error: 'missing fields' }, 400);
		}
		const jobs = messages.map((m: any) => ({
			body: {
				phone_number_id,
				access_token,
				callback_url,
				message_id: m.message_id,
				to: m.to,
				template_name: m.template_name,
				language: m.language,
				components: m.components || [],
			} as Job,
		}));
		// Queue.sendBatch caps at 100 messages per call.
		for (let i = 0; i < jobs.length; i += 100) {
			await env.CAMPAIGN_QUEUE.sendBatch(jobs.slice(i, i + 100));
		}
		return json({ ok: true, queued: messages.length }, 202);
	},

	async queue(batch: MessageBatch<Job>, env: Env): Promise<void> {
		const byCallback: Record<string, Result[]> = {};
		for (const msg of batch.messages) {
			const job = msg.body;
			try {
				const res = await sendOne(job, env);
				(byCallback[job.callback_url] ||= []).push(res);
				msg.ack();
			} catch {
				// Transient (rate limit / network) — let Cloudflare retry with
				// backoff. Don't report or ack: a later attempt may still send.
				msg.retry({ delaySeconds: 30 });
			}
		}
		await Promise.all(
			Object.entries(byCallback).map(([cb, results]) => postStatus(cb, results, env)),
		);
	},
} satisfies ExportedHandler<Env, Job>;

// --- Meta send ---

async function sendOne(job: Job, env: Env): Promise<Result> {
	const v = env.META_GRAPH_VERSION || 'v18.0';
	const url = `https://graph.facebook.com/${v}/${job.phone_number_id}/messages`;
	const body = {
		messaging_product: 'whatsapp',
		recipient_type: 'individual',
		to: job.to,
		type: 'template',
		template: {
			name: job.template_name,
			language: { code: job.language },
			components: job.components || [],
		},
	};
	const resp = await fetch(url, {
		method: 'POST',
		headers: { Authorization: `Bearer ${job.access_token}`, 'Content-Type': 'application/json' },
		body: JSON.stringify(body),
	});
	const data: any = await resp.json().catch(() => ({}));
	if (resp.ok && data.messages && data.messages[0]) {
		return { message_id: job.message_id, status: 'sent', wamid: data.messages[0].id };
	}
	const code = data?.error?.code;
	// 429 / Meta rate-limit codes → throw so the queue retries; anything else
	// is a permanent failure for this message.
	if (resp.status === 429 || code === 130429 || code === 80007 || code === 131048) {
		throw new Error('rate-limited');
	}
	const err = data?.error?.error_user_msg || data?.error?.message || `HTTP ${resp.status}`;
	return { message_id: job.message_id, status: 'failed', error: String(err).slice(0, 250) };
}

// --- Status callback to Odoo (HMAC signed the same way) ---

async function postStatus(callbackUrl: string, results: Result[], env: Env): Promise<void> {
	const body = JSON.stringify({ results });
	const sig = await hmacHex(env.CAMPAIGN_SECRET, body);
	await fetch(callbackUrl, {
		method: 'POST',
		headers: { 'Content-Type': 'application/json', 'X-Soukbot-Signature': sig },
		body,
	}).catch(() => {
		/* Odoo unreachable — rows stay 'dispatched'; safe to reconcile later */
	});
}

// --- helpers ---

async function hmacHex(secret: string, body: string): Promise<string> {
	const key = await crypto.subtle.importKey(
		'raw',
		new TextEncoder().encode(secret),
		{ name: 'HMAC', hash: 'SHA-256' },
		false,
		['sign'],
	);
	const sig = await crypto.subtle.sign('HMAC', key, new TextEncoder().encode(body));
	return [...new Uint8Array(sig)].map((b) => b.toString(16).padStart(2, '0')).join('');
}

function safeEqual(a: string, b: string): boolean {
	if (a.length !== b.length) return false;
	let r = 0;
	for (let i = 0; i < a.length; i++) r |= a.charCodeAt(i) ^ b.charCodeAt(i);
	return r === 0;
}

function json(obj: unknown, status = 200): Response {
	return new Response(JSON.stringify(obj), {
		status,
		headers: { 'Content-Type': 'application/json' },
	});
}
