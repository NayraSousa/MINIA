const conn = require('../databases/conn');
const { listAll } = require('../services/UserService');

module.exports = {
    async create(name, email, login, password) {
        const user = (await conn('user').insert(
            {
                name,
                email,
                login, 
                password
            }
        ))
        return user;
    },

    async listAll() {
        const users = await conn('user').select(
            'id',
            'name',
            'login',
            'email'
        )
        return users;
    }
}