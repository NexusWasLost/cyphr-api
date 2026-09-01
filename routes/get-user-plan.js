import { Hono } from "hono";
import { neon } from "@neondatabase/serverless";
import { decryptKey } from "../utils/encrypt.js";
import { HTTPException } from "hono/http-exception";

const userplan = new Hono();

userplan.get("/user/plan", async function(c){
    const meta = c.get("meta");
    if (!meta)
        throw new HTTPException(401, { message: "User context not found (Unauthorized) !" });

    const id = meta.uid; //this is user id

    const sql = neon(c.env.DATABASE_URL);
    //get current active plan
    const data = await sql.query(
        `SELECT user_plans.user_plan_id, plans.name, plans.key_limit
        FROM user_plans
        INNER JOIN plans ON user_plans.plan_id = plans.plan_id
        WHERE user_plans.user_plan_status = $1 AND user_plans.user_id = $2`,
        ['active', id]
    );
    if(data.length === 0)
        throw new HTTPException(404, { message: "No valid plan found for this user !"});

    return c.json({
        success: true,
        message: "Retrieve Success",
        data: data
    });
});

export default userplan;
