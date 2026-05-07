const CandidateRepository = require('../repository/CandidateRepository');
const recruiterRepository = require('../repository/RecruiterRepository');
const { listById, update } = require('./CandidateService');

module.exports = {
    async create (user_id, company_id, departament, responsability) {
        return recruiterRepository.create(user_id, company_id, departament, responsability);

    },

    async listAll() {
        return recruiterRepository.listAll();

    },

    async listById(id) {
        return recruiterRepository.listById(id);

    },

    async listByUserId(user_id) {
        return recruiterRepository.listByUserId(user_id);

    },

    async update(id, data) {
        return recruiterRepository.update(id, data);

    },

    async delete(id) {
        return CandidateRepository.delete(id);
        
    }
}