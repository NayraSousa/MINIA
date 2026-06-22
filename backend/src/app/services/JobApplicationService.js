const jobApplicationRepository = require('../repository/JobApplicationRepository');

module.exports = {
    async create(candidate_id, job_id, curriculum, status, ai_score, created_at){
        return jobApplicationRepository.create(candidate_id, job_id, curriculum, status, ai_score, created_at);
    },

    async listAll() {
        return jobApplicationRepository.listAll();
    },

    async listById(id) {
        return jobApplicationRepository.listById(id);
    },

    async listByJobId(job_id) {
        return jobApplicationRepository.listByJobId(job_id);
    },

    async update(id, data) {
        return jobApplicationRepository.update(id, data);
    },

    async delete(id) {
        return jobApplicationRepository.delete(id);
    }
}