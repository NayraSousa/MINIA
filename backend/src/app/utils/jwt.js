const jwt = require('jsonwebtoken')
const config = require('../configs/jwt.config.json')
module.exports = {
    generateJwt(params = {}){
        return jwt.sign(params, config.secret, {
            expiresIn: config.expiration
        })
    }
}