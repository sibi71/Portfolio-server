const mongoose = require("mongoose")

const userSchema =  new mongoose.Schema({
    name:{
        type:String,
    },
    email:{
        type:String,
        required:true,
        unique:true,
    },
    password:{
        type:String,
        required:true,
    },
    verified:{
        type:Boolean,
        default:false,
    }
},{timestamps:true})

const user  = mongoose.model("users",userSchema)

module.exports = user