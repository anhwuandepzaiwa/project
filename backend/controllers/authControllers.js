const User = require("../models/User");
const jwt = require("jsonwebtoken");
const bcrypt = require("bcrypt");

const authController = {
    //REGISTER
    registerUser: async(req, res) => {
        try {
            const salt = await bcrypt.genSalt(10);
            const hashed = await bcrypt.hashe(req.body.password, salt);

            //Create new user
            const newUser = await new User({
                username: req.body.username,
                email: req.body.email,
                password: hashed
            });

            //Save to DB
            const user = await newUser.save();
            res.status(200).json(user);
        } catch (err) {
            res.status(500).json(err);
        }
    },
    //GENERATE ACCESS TOKEN
    generateAccessToken: (user)=>{
        return jwt.sign({
            id: user.id,
            admin: user.admin
        },
        process.env.JWT_ACCESS_KEY,
        {expiresIn: "30s"}
    );
    },
    //GENERATE REFRESH TOKEN
    generateRefreshToken: (user)=>{  
        return jwt.sign({
            id: user.id,
            admin: user.admin
        },
        process.env.JWT_ACCESS_KEY,
        {expiresIn: "365d"}
    );
    },
    //LOGIN
    loginUser: async(req, res) =>{
        try {
            const user = await User.findOne({ username: req.body.username });
            if(!user){
                res.status(404).json("Wrong username!");
            }
            const validPassword = await bcrypt.compare(
                req.body.password,
                user.password
            );
            if(!validPassword){
                res.status(404).json("Wrong password");
            }
            if(user && validPassword){
                const accessToken = authController.generateAccessToken(user);
                const refreshToken = authController.generateRefreshToken(user);
            const {password, ...others} = user._doc;
                res.status(200).json(...others, accessToken, refreshToken);
            }
        } catch (err) {
            res.status(500).json(err);
        }
    }
}