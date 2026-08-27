import { HTTPException } from "hono/http-exception";

export const rateLimiter = async function (c, next) {
    const meta = c.get("meta");
    if (!meta)
        throw new HTTPException(401, { message: "User context not found (Unauthorized) !" });

    const id = meta.uid;

    let success = false;
    try {
        //set rate limiter key
        const res = await c.env.RATE_LIMIT.limit({ key: id });
        success = res.success;
    }
    catch (error) {
        throw new HTTPException(500, {
            message: "Rate limit check failed",
            cause: error
        });
    }

    if (!success) {
        throw new HTTPException(429, {
            message: "Halt ! Too many Requests !"
        });
    }

    await next();
}
