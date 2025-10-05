import "dotenv/config";
import express from "express";
import { env } from "./config/env";
import authRoute from "./routes/auth.route";
import { errorHandler } from "./middleware/errorHandler";
import cookieParser from "cookie-parser";
import cors from "cors";

const app = express();

app.use(
  cors({
    allowedHeaders: "*",
    credentials: true,
  })
);
app.use(express.json());
app.use(cookieParser());
app.use("/api/v1/auth", authRoute);
app.get("/health", (req, res) => {
  res.json({ message: "Done" });
});

app.use(errorHandler);

app.listen(env.PORT, () => {
  console.log(`Server running at http://localhost:${env.PORT}`);
});
