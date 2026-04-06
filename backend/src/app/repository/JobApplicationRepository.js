const conn = require('../databases/conn');

module.exports = {
    async create(candidate_id, job_id, status, ai_score, created_at) {
        const [jobApplication] = (await conn('job_application').insert(
            {
                candidate_id,
                job_id,
                status,
                ai_score,
                created_at
            }
        ).returning(['id', 'status']));

        return jobApplication;
    },

    async listAll() {
        const jobs = await conn('job_application').select(
            'id',
            'candidate_id',
            'job_id',
            'status',
            'ai_score'
        );

        return jobs;
    },

    async listById(id) {
        const jobApplicationFiltered = await conn('job_application').select(
            'id',
            'candidate_id',
            'job_id',
            'status',
            'ai_score'
        ).where('id', id);

        return jobApplicationFiltered;
    },

    async update(id, data){
        const jobApplicationUpdated = await conn('job_application')
            .where( { id })
            .update(data)
            .returning(['id']);
        
        return jobApplicationUpdated;
    },

    async delete(id) {
        const jobApplicationDeleted = await conn('job_application')
            .where( { id })
            .delete()
            .returning(['id']);

        return jobApplicationDeleted;
    }
}