const bcrypt = require('bcryptjs')

module.exports = {
    async encrypt(password) {
        const saltRounds = 10;
        const hash = await bcrypt.hash(password, saltRounds);

        return hash;
    }

}