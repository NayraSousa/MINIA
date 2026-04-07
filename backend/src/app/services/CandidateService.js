const candidateRepository = require('../repository/CandidateRepository');

module.exports = {
    async create (user_id, linkedin_url, github_url) {
        return candidateRepository.create(user_id, linkedin_url, github_url);
    },

    async listAll() {
        return candidateRepository.listAll();
    },

    async listById(id) {
        return candidateRepository.listById(id);
    },

    async listByUser(user_id) {
        return candidateRepository.listByUser(user_id);
    },

    async update(id, data) {
        return candidateRepository.update(id, data);
    },

    async delete(id) {
        return candidateRepository.delete(id);
    }
}