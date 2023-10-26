import express from "express";
import * as dotenv from "dotenv";
import cors from "cors";
import mongoose from "mongoose";
import morgan from "morgan";
import helmet from "helmet";
import apiRouter from "./routes/apiRoutes.js";
import { rateLimit } from "express-rate-limit";

// Const declarations
dotenv.config();
const app = express();
const PORT = process.env.PORT;
const MONG_URI = process.env.MONG_URI;

// Rate Limiter
const limiter = rateLimit({
  windowMs: 60 * 1000,
  max: 120,
  message: "Too many requests. IP blocked.",
  standardHeaders: true,
  legacyHeaders: false,
});

// Middlewares
const corsOptions = {
  origin:
    process.env.NODE_ENV === "production"
      ? [
          "https://facottry-website.vercel.app", 
        ]
      : "http://localhost:3000",
  credentials: true,
  optionSuccessStatus: 200,
};
app.use(cors(corsOptions));

if (process.env.NODE_ENV === "production") app.set("trust proxy", 1);
app.use(express.json());
app.use(morgan("tiny"));
app.use(helmet());
app.use(limiter);

// Database Connenction
mongoose
  .connect(MONG_URI)
  .then(
    app.listen(PORT, () => {
      if (process.env.NODE_ENV === "production") {
        console.log("Production Ready");
      } else {
        console.log(`Server:http://localhost:${PORT}/`);
      }
    })
  )
  .catch((err) => {
    console.log(err);
  });

// Root Route
app.get("/", (req, res) => {
  return res.send("FacOTTry");
});

app.use("/api", apiRouter);