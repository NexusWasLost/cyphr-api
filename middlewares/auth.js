import { HTTPException } from "hono/http-exception";
import { jwtVerify, createLocalJWKSet } from "jose";

let MEMORY_CACHE_JWKS = null;

//verify token and return custom payload
async function verifyToken(c, token, JWKS) {
    //create a local JWK set from JWKS JSON
    const jsonWebKeySet = createLocalJWKSet(JWKS);

    const content = await jwtVerify(token, jsonWebKeySet, {
        issuer: `https://${c.env.SUPABASE_PROJECT_ID}.supabase.co/auth/v1`,
        audience: "authenticated"
    });

    const customPayload = {
        uid: content.payload.sub,
        email: content.payload.email
    }

    return customPayload;
}

export const authMiddleware = async function (c, next) {
    const authHeader = c.req.header("Authorization");

    if (!authHeader || !authHeader.startsWith("Bearer ")) {
        throw new HTTPException(401, {
            message: "Missing Auth Header or invalid auth header"
        }
        );
    }

    const token = authHeader.split(" ")[1];

    try {
        // CACHE LAYER 1: RAM
        if (MEMORY_CACHE_JWKS) {
            try {
                const user = await verifyToken(c, token, MEMORY_CACHE_JWKS);
                c.set("meta", user);
                return await next();
            }
            catch (e) {
                // Stale RAM? Clear it and move to KV/Fetch
                MEMORY_CACHE_JWKS = null;
            }
        }

        // CACHE LAYER 2: KV Cache
        const kvJWKS = await c.env.API_CACHE.get("JWKS", "json");
        if (kvJWKS) {
            try {
                const user = await verifyToken(c, token, kvJWKS);
                MEMORY_CACHE_JWKS = kvJWKS; // Sync RAM
                c.set("meta", user);
                return await next();
            }
            catch (e) {
                // Stale KV? Don't return next(), let it fall through to fetch
                console.log("KV JWKS stale, fetching fresh...");
            }
        }

        //fetch JSON Web Key Set
        const JWKS_response = await fetch(`https://${c.env.SUPABASE_PROJECT_ID}.supabase.co/auth/v1/.well-known/jwks.json`, {
            method: "GET"
        });
        if (!JWKS_response.ok) throw new Error("Failed to fetch fresh JWKS...");

        const freshJWKS = await JWKS_response.json();
        //cache in isolate memory
        MEMORY_CACHE_JWKS = freshJWKS;
        //cache the JWKS in KV
        c.executionCtx.waitUntil(c.env.API_CACHE.put("JWKS", JSON.stringify(freshJWKS), {
            expirationTtl: 600
        }));

        const customPayload = await verifyToken(c, token, freshJWKS);
        c.set("meta", customPayload);
        await next();
    }
    catch (error) {
        throw new HTTPException(401, {
            message: "Authentication failed",
            cause: error
        });
    }
}
