const conn = require('../databases/conn');

module.exports = {
    async create(candidate_id, job_id, curriculum, status, ai_score) {
        const [jobApplication] = (await conn('job_application').insert(
            {
                candidate_id,
                job_id,
                curriculum,
                status,
                ai_score,
            }
        ).returning(['id', 'status']));

        return jobApplication;
    },

    async listAll() {
        const jobs = await conn('job_application').select(
            'id',
            'candidate_id',
            'job_id',
            'curriculum',
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
            'curriculum',
            'status',
            'ai_score'
        ).where('id', id);

        return jobApplicationFiltered;
    },

    async listByJobId(job_id) {
        const jobApplications = await conn('job_application')
            .leftJoin('candidate', 'job_application.candidate_id', 'candidate.id')
            .leftJoin('user', 'candidate.user_id', 'user.id')
            .select(
                'job_application.id',
                'job_application.candidate_id',
                'job_application.job_id',
                'job_application.curriculum',
                'job_application.status',
                'job_application.ai_score',
                'job_application.created_at',
                'user.name as candidate_name',
                'user.email as candidate_email'
            )
            .where('job_application.job_id', job_id)
            .orderBy([
                { column: 'job_application.ai_score', order: 'desc' },
                { column: 'job_application.created_at', order: 'desc' }
            ]);

        return jobApplications;
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