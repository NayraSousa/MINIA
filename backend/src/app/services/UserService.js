const userRepository = require('../repository/UserRepository')
const encrypt = require('../utils/encryptPassword');
const candidateService = require('./CandidateService');
const recruiterService = require('./RecruiterService');

module.exports = {
    async create(name, email, login, password, role, github_url, linkedin_url, company_id) {
        const passCrypted = await encrypt.encrypt(password);
        user = await userRepository.create(name, email, login, passCrypted, role);

        if (role === "candidate"){
            candidateService.create(user.id, linkedin_url, github_url)
        }
        else if (role === "recruiter") {
            recruiterService.create(user.id, company_id)
        }
        return user
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