const userRepository = require('../repository/UserRepository')
const encrypt = require('../utils/encryptPassword')

module.exports = {
    async create(name, email, login, password) {
        const passCrypted = await encrypt.encrypt(password);
        return userRepository.create(name, email, login, passCrypted);
    },

    async listAll() {
        return userRepository.listAll();
    },

    async listById(id) {
        return userRepository.listById(id);

    },

    async update(id, data) {
        return userRepository.update(id, data);
    },

    async delete(id) {
        return userRepository.delete(id);
    }
}