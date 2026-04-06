const jwt = require('jsonwebtoken')
const config = require('../configs/jwt.config')

module.exports = (request, response, next) => {
    const authorization = request.headers.authorization

    if(!authorization) {
        return response.status(401)
        .send({error: "Token not provided"})
    }

    const parts = authorization.split(' ')
    if (parts.length !== 2){
        return response.status(401)
            .send({error: "Token format invalid"})
    }
    
    const [scheme, token] = parts

    if (!/^Bearer$/i.test(scheme)) {
        return response.status(401)
            .send({ error: "Token malformatted" })
    }

    jwt.verify(token, config.secret, (err, decoded) => {
        if(err){
            response.status(401)
                .send({error: "Token invalid"})
            return
        }

        request.userId = decoded.userId
        return next()
    })
}