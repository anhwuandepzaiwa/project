const express = require("express");
const cors = require("cors");
const dotenv = require("dotenv");
const mongoose = require("mongoose");
const cookieParser = require("cookie-parser");
const authroute = require("./routes/auth");
const userRoute = require("./routes/user");

dotenv.config();
const app = express();

mongoose.connect(process.env.MONGODB_URL, () => {
    console.log("CONNECTED TO MONGODB");
})

app.use(cors());
app.use(cookieParser());
app.use(express.json());

// ROUTES
app.use("/v1/auth", authroute);
app.use("/v1/user", userRoute);

app.listen(8000, () => {
    console.log("Server is running");
});

// AUTHENTICATION