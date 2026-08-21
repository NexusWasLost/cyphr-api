import { Hono } from "hono";
import { neon } from "@neondatabase/serverless";
import { encryptKey } from "../utils/encrypt.js";
import { createKeyHint } from "../utils/createHint.js";
import { HTTPException } from "hono/http-exception";

const addkey = new Hono();

addkey.post("/add-key", async function (c) {
    const { serviceName, apiKeyName, apiKeyValue } = await c.req.json();

    if (!serviceName || !apiKeyName || !apiKeyValue) {
        throw new HTTPException(400, { message: "All fields must be provided" });
    }

    const meta = c.get("meta");
    if(!meta)
        throw new HTTPException(401, { message: "User context not found (Unauthorized) !"});

    //create key hint
    const keyHint = createKeyHint(apiKeyValue);
    //encrypt key before insert
    const encryptedAPIKeyValue = await encryptKey(c, apiKeyValue);

    const sql = neon(c.env.DATABASE_URL);

    //insert user data in one atomic transaction (also check if limit exceeded)
    const res = await sql.transaction([
        sql.query(`
            INSERT INTO users(user_id, user_email)
            VALUES($1, $2)
            ON CONFLICT (user_id) DO NOTHING;`,
            [meta.uid, (meta.email || null)]
        ),
        sql.query(`
            SELECT user_id FROM users WHERE user_id = $1 FOR UPDATE;`,
            [meta.uid]
        ),
        sql.query(`
            INSERT INTO api_keys(user_id, key_name, encrypted_key, key_hint, service_name)
            SELECT $1, $2, $3, $4, $5
            WHERE (SELECT COUNT(*) FROM api_keys WHERE user_id = $1) < $6
            RETURNING key_id;`,
            [meta.uid, apiKeyName, encryptedAPIKeyValue, keyHint, serviceName, c.env.FREE_CAP]
        )
    ]);

    //check if the data was inserted
    if(res[2].length === 0){
        throw new HTTPException(402, { message: "LIMIT REACHED of free 10 API Keys !" });
    }

    c.executionCtx.waitUntil(c.env.API_CACHE.delete(`keys:${meta.uid}`));

    return c.json({
        success: true,
        message: "Key Added Successfully",
        data: {
            key_id: res[2].key_id,
            key_name: apiKeyName,
            key_hint: keyHint,
            service_name: serviceName
        }
    }, 200);
});

export default addkey;
