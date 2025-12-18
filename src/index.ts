import express from "express";
import type { Request, Response } from "express";
import cors from "cors";
import dotenv from "dotenv";

dotenv.config();

const app = express();
const port = 8000;

app.use(express.json({ limit: "16kb" }));
app.use(express.urlencoded({ extended: true, limit: "16kb" }));
app.use(
  cors({
    origin: "http://localhost:3000",
    credentials: true,
    methods: ["GET", "POST", "PUT", "DELETE"], // Ensure needed methods are allowed
    allowedHeaders: ["Content-Type", "Authorization"], // Allow necessary headers
  })
);

app.get("/", (req: Request, res: Response) => {
  res.send("Hello world");
});

// routes
import urlRouter from "./route/url-route.js";
app.use("/v1/api/url", urlRouter);

// error middleware
import errorHandler from "./middleware/error-middleware.js";
app.use(errorHandler);

app.listen(port, () => {
  console.log(`Server is running on http://localhost:${port}`);
});
