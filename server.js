import express from "express";
import cors from "cors";
import cookieParser from "cookie-parser";
import "dotenv/config";
import connectDB from "./config/mongodb.js";
import authRoutes from "./routes/authRoutes.js"

const app = express();
const port = process.env.PORT || 4000 ;

connectDB();
app.use(cookieParser());
app.use(express.json());
app.use(cors({credentials: true}));

// Api endpoints
app.get('/', (req, res) => res.send('Api working'));
app.use('/api/auth', authRoutes)

app.listen(port, () => console.log(`server is listning on port ${port}`));