const conn = require('../databases/conn');

module.exports = {
    async create(name, description, recruiter_id, company_id, created_by) {
        const [job] = (await conn('job').insert(
            {
                name, 
                description,
                recruiter_id,
                company_id,
                created_by
            }
        ).returning(['id', 'name']));

        return job;
    },

    async listAll() {
        const jobs = await conn('job').select(
            'id',
            'name', 
            'description',
            'created_by'
        );

        return jobs
    },

    async listById(id) {
        const jobFiltered = await conn('job').select(
            'id',
            'name',
            'description',
            'created_by'
        ).where('id', id);

        return jobFiltered;
    },

    async update(id, data) {
        const jobUpdated = await conn('job')
            .where( { id })
            .update(data)
            .returning(['id', 'name']); //seria bom retornar os campos que foram atualizados

        return jobUpdated;
    },

    async delete(id) {
        const jobDeleted = await conn('job')
            .where( { id })
            .delete()
            .returning(['id', 'name']);

        return jobDeleted;
    }
}