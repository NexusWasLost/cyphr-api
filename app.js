import { Hono } from "hono";
import { cors } from "hono/cors";
import { authMiddleware } from "./middlewares/auth.js";
import { errorHandler } from "./middlewares/error-handler.js";
import { rateLimiter } from "./middlewares/rate-limiter.js";

import addkey from "./routes/add-key.js";
import getkey from "./routes/get-key.js";
import updatekey from "./routes/update-key.js";
import delkey from "./routes/del-key.js";
import deluser from "./routes/del-user.js";

const app = new Hono();
app.onError(errorHandler);

app.use("*", cors({
    origin: [
        "https://cyphr.pages.dev",
        "http://127.0.0.1:5501"
    ],
    allowMethods: ["GET", "POST", "PATCH","DELETE"],
    maxAge: 600
}));

app.use("*", authMiddleware);
app.use("*", rateLimiter);

app.route("/api", addkey);
app.route("/api", getkey);
app.route("/api", updatekey);
app.route("/api", delkey);
app.route("/api", deluser);

export default app;
