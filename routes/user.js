const router = require("express").Router()
const bcrypt = require ("bcrypt")
const jwt = require("jsonwebtoken")
const user = require("../models/user")
const verifyToken = require("../middleware/verifyToken")
const nodemailer = require("nodemailer")

router.get("/",(req,res)=>{
    res.json({msg:"route is working on user"})
})

router.post("/signup",async(req,res)=>{

    const salt = await bcrypt.genSalt(10);
    const passwordHash = await bcrypt.hash(req.body.password, salt);

    const User = await user.create({
        name:req.body.name,
        email:req.body.email,
        password:passwordHash,

    })
    const token = jwt.sign({id: User._id},process.env.SECRET_KEY)
    const transporter = nodemailer.createTransport({
        service:"gmail",
        auth:{
            user:"thetemp24@gmail.com",
            pass:process.env.MAIL_PWD,
        },
    });
    let info = await transporter.sendMail({
        from:"<thetemp24@gmail.com>",
        to:req.body.email,
        subject:"Verify your Email",
        html:`
        <div>
        <strong>${req.body.name}</strong> we welcome to our platform.
        <a href="http://localhost:3000/user/verify/${token}">Verify Email</a>
        </div>
        `,
    });
        if(info){
            console.log(info);
        }
        res.json({msg:"Account created successfully. please verify your email "})

})

router.post("/login",async(req,res)=>{
    let { email,password} = req.body;

    const result = await user.findOne({email:email});

    if(result){
        if(result.verified){
                bcrypt.compare(password, result.password).then((passwordResult)=>{
                    if(passwordResult){
                            jwt.sign({userId:result._id},process.env.SECRET_KEY,(err,token)=>{
                                if(err){
                                    console.log(err);
                                }
                                else{
                                    return res.json({
                                        success:true,
                                        msg:"login successful",
                                        token
                                    })
                                }
                            });
                    }
                    else{
                        return res.json({success:false,msg:"incorrect password"});
                    }
                });
        }
        else{
            return res.json({success:false,msg:"Please verify your email"});

        }

    }else{
        return res.json({success:false,msg:"User not registered"});
    }
})


router.get("/data",verifyToken,(req,res)=>{
    return res.json(req.user)

})

router.get("/verify/:token",async(req,res)=>{
    const token = jwt.verify(req.params.token,process.env.SECRET_KEY,async(err,decoded)=>{
        if(err){
            return res.json({msg:"Link expired",success:false})
        }
        const id = decoded.id ;
        await user.findByIdAndUpdate(id, {verified:true});
        return res.json({msg:"Account verified successfully", success:true})

    })
})


module.exports = router