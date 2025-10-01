import "dotenv/config";
import express from "express";
import { env } from "./config/env";
import authRoute from "./routes/auth.route";
import { errorHandler } from "./middleware/errorHandler";

const app = express();

app.use(express.json());

app.use("/api/v1/auth", authRoute);

app.use(errorHandler);

app.listen(env.PORT, () => {
  console.log(`Server running at http://localhost:${env.PORT}`);
});
