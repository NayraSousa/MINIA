const userService = require('../services/UserService')

module.exports = {
    async create (request, response) {
        const {name, email, login, password} = request.body;
        return userService.create(name, email, login, password);
        
    // return response.status(201).status(
    //     {
    //         mensagem: {
    //             "User Created": {
    //                 "name": name,
    //                 "email": email,
    //                 "login": login,
    //                 "password": passCrypted
    //             }
    //         }
    //     }
    // )
    },
    async listAll(request, response) {
        return userService.listAll();
    },

    async listById(request, response) {
        const { id } = request.params;
        const userFiltered = await conn('user').select(
            'id',
            'name',
            'login',
            'email'
        ).where(
            'id', id
        )
        return response.status(200).json({userFiltered})
    },

    async update(request, response){

    }
}