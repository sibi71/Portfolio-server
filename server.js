const express = require("express");
const bodyParser = require("body-parser")
require("dotenv").config();
const connectDB = require("./config/db")
const apiRouter = require("./routes")
const cors = require("cors")
const app = express();


const port = process.env.PORT || 4000 ;

connectDB();

app.use(cors())

app.use(express.json())

app.use(bodyParser.urlencoded({extended:true}))

app.use("/api",apiRouter)



app.get("/",(req,res)=>{
    res.json("Api is Working ON")
})


app.listen(port ,(req,res)=>{
    console.log(`server is up and runing on port ${port}`);
})