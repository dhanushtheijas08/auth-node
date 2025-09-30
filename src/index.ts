import "dotenv/config";
import express, { Request, Response } from "express";
import { env } from "./config/env";

const app = express();

app.get("/", (req: Request, res: Response) => {
  res.send("Hello, Express + TypeScript + Yarn 🚀");
});

app.listen(env.PORT, () => {
  console.log(`Server running at http://localhost:${env.PORT}`);
});
