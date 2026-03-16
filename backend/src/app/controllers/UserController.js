const userService = require('../services/UserService')

module.exports = {
    async create (request, response) {
        const {name, email, login, password} = request.body;
        user = await userService.create(name, email, login, password);
        
        return response.status(201).json(
            {
                mensagem: {
                    "User Created": {
                        user
                    }
                }
            }
        )
    },
    async listAll(request, response) {
        users = await userService.listAll();
        return response.status(200).json(
            {
                users
            }
        )
    },

    async listById(request, response) {
        const { id } = request.params;
        const userFiltered = await userService.listById(id);
        return response.status(200).json({userFiltered})
    },

    async update(request, response){
        const { id } = request.params;
        const data = Object.fromEntries(
            Object.entries(request.body).filter(([_, v]) => v !== undefined)
        );

        userUpdated = await userService.update(id, data);
        return response.status(200).json({userUpdated});
    },

    async delete (request, response) {
        const { id } = request.params;
        const userDeleted = await userService.delete(id);

        return response.status(200).json({userDeleted});

    }
}