const jobRepository = require('../repository/JobRepository');

module.exports = {
    async create(name, description, recruiter_id, company_id, created_by){
        return jobRepository.create(name, description, recruiter_id, company_id, created_by);
    },

    async listAll() {
        return jobRepository.listAll();
    },

    async listById(id) {
        return jobRepository.listById(id);
    },

    async listByRecruiterId(recruiter_id) {
        return jobRepository.listByRecruiterId(recruiter_id);
    },

    async update(id, data) {
        return jobRepository.update(id, data);
    },

    async delete(id) {
        return jobRepository.delete(id);
    }
}