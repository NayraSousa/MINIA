const conn = require('../databases/conn')
const bcrypt = require('bcryptjs')
const jwt = require('../utils/jwt')

module.exports = {
    async auth(request, response) {
        const { login, password} = request.body
        const user = (await conn('user')
            .where('login', login)
            .select()
            .first())
        if(!user){
            return response.status(404).send({error: "User not found"})
        }
        
        if(!await bcrypt.compare(password, user.password)) {
            return response.status(401)
                .send({error: "Password incorrect"})
        }
        user.password = undefined
        const token = jwt.generateJwt({ id: user.id })

        response.send({
            user,
            token: token
        })
    }
}