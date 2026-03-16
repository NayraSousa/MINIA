const { listAll } = require('../controllers/UserController');
const userRepository = require('../repository/UserRepository')
const encrypt = require('../utils/encryptPassword')

module.exports = {
    async create(name, email, login, password) {
        const passCrypted = encrypt(password);
        return userRepository.create(name, email, login, passCrypted);
    },

    async listAll() {
        return userRepository.listAll()
    }
}