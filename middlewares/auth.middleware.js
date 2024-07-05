const jwt = require("jsonwebtoken")

function isTokenValid (req, res, next) {
    try {
        const token = req.headers.authorization.split(" ")[1]

        const payload = jwt.verify(token, process.env.TOKEN_SECRET)
        req.payload = payload

        next()
    } catch (error) {
        res.status(401).json({errorMessage: "Token is not valid or doesn't exist"})
    }
}

//* ⤴️ EXPORTS
module.exports = {
    isTokenValid
  }