const conn = require('../databases/conn');
const { listAll, listById } = require('./CandidateRepository');

module.exports = {
    async create(user_id, company_id, departament, responsability){
        const [recruiter] = await conn('recruiter').insert(
            {
                user_id,
                company_id,
                departament,
                responsability
            }
        ).returning(['id']);
        return recruiter;
    },

    async listAll() {
        const recruiters = await conn('recruiter').select(
            'id',
            'user_id',
            'company_id',
            'departament',
            'responsability'
        );
        return recruiters;
    },

    async listById(id) {
        const recruiterFiltered = await conn('recruiter').select(
            'id',
            'user_id',
            'company_id',
            'departament',
            'responsability'
        ).where('id', id);
        return recruiterFiltered;
    },

    async listByUserId(user_id) {
        const recruiterFiltered = await conn('recruiter').select(
            'id',
            'user_id',
            'company_id',
            'departament',
            'responsability'
        ).where('user_id', user_id).first();

        return recruiterFiltered;
    },

    async update(id, data) {
        const recruiterUpdated = await conn('recruiter')
            .where({ id })
            .update(data)
            .returning(['id']);
        
        return recruiterUpdated;
    },

    async delete(id) {
        const recruiterDeleted = await conn('recruiter')
            .where( { id })
            .delete()
            .returning(['id']);

        return recruiterDeleted;
    }
}