const conn = require('../databases/conn');

module.exports = {
    async create(name, email, login, password) {
        const [user] = (await conn('user').insert(
            {
                name,
                email,
                login, 
                password
            }
        ).returning(['id', 'name', 'email']));
        return user;
    },

    async listAll() {
        const users = await conn('user').select(
            'id',
            'name',
            'login',
            'email'
        );
        return users;
    },

    async listById(id) {
        const userFiltered = await conn('user').select(
            'id',
            'name',
            'login',
            'email'
        ).where(
            'id', id
        );

        return userFiltered;
    },

    async update(id, data) {
        const userUpdated = await conn('user')
            .where({ id })
            .update(data)
            .returning(['id', 'name', 'email']);
        
        return userUpdated;
    },

    async delete(id) {
        const userDeleted = await conn('user')
        .where( { id })
        .delete()
        .returning(['id', 'name', 'email']);

        return userDeleted;
    }
}