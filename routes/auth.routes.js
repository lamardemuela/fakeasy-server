const User = require("../models/User.model");
const router = require("express").Router();
const bcrypt = require("bcryptjs");
const jwt = require("jsonwebtoken");
const { isTokenValid } = require("../middlewares/auth.middleware")

// 👇🏻 AUTH ROUTES

// POST "/api/auth/signup"
router.post("/signup", async(req, res, next) => {
    const { name, email, password } = req.body

    // validacion campos requeridos
    if(!name | !email | !password) {
        res.status(400).json({errorMessage: "All fields are mandatory"})
        return
    }

    // validacion formato email
    const emailRegex = /[a-z0-9!#$%&'*+/=?^_`{|}~-]+(?:\.[a-z0-9!#$%&'*+/=?^_`{|}~-]+)*@(?:[a-z0-9](?:[a-z0-9-]*[a-z0-9])?\.)+[a-z0-9](?:[a-z0-9-]*[a-z0-9])?/gm
    if(emailRegex.test(email) === false){
        res.status(400).json({errorMessage: "The email format is not correct."})
        return
    }

    // validacion seguridad password
    const passwordRegex = /^(?=.*\d)(?=.*[a-z])(?=.*[A-Z])(?=.*[a-zA-Z]).{8,}$/gm
    if(passwordRegex.test(password) === false) {
        res.status(400).json({errorMessage: "The password must be at least 8 characters long, and include one lowercase letter, one uppercase letter, and one special character."})
        return
    }

    // encriptacion
    const salt = await bcrypt.genSalt(12)
    const hashPassword = await bcrypt.hash(password, salt)

    // creacion user
    try {
        const foundUser = await User.findOne({email: email})
        console.log(foundUser);
        if(foundUser){
            res.status(400).json({errorMessage: "This email is already registered"})
            return
        }

        await User.create({
            name,
            email,
            password: hashPassword
        })

        res.sendStatus(201)
    } catch (error) {
        next(error)
    }

})

// POST "/api/auth/login"
router.post("/login", async (req, res, next) => {
    const { email, password } = req.body

    // validacion campos requeridos
    if(!email | !password) {
        res.status(400).json({errorMessage: "All fields are mandatory"})
        return
    }

    try {
        // validacion email
        const foundUser = await User.findOne({email: email})
        if(!foundUser){
            res.status(400).json({errorMessage: "User is not registered"})
            return
        }

        // validacion password
        const isPasswordCorrect = await bcrypt.compare(password, foundUser.password)
        if(isPasswordCorrect === false){
            res.status(400).json({errorMessage: "Password is incorrect"})
            return
        }

        // payload
        const payload = {
            _id: foundUser._id,
            email: foundUser.email
        }

        // token
        const authToken = jwt.sign(payload, process.env.TOKEN_SECRET, {algorithm: "HS256", expiresIn:"365d"})

        res.status(200).json({authToken: authToken})
    } catch (error) {
        next(error)
    }
})

// GET "/api/auth/verify"
router.get("/verify", isTokenValid, (req, res, next) => {
    res.status(200).json({payload: req.payload})
})

module.exports = router;