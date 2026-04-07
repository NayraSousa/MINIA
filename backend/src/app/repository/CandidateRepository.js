const conn = require('../databases/conn');

module.exports = {
    async create(user_id, linkedin_url, github_url) {
        const [candidate] = await conn('candidate').insert(
            {
                user_id,
                linkedin_url,
                github_url
            }
        ).returning(['id']); //a ideia no futuro é retornar as informações do user_id
        return candidate;
    },

    async listAll() {
        const candidates = await conn('candidate').select(
            'id',
            'user_id',
            'linkedin_url',
            'github_url'
        );

        return candidates;
    },

    async listById(id) {
        const candidateFiltered = await conn('candidate').select(
            'id',
            'user_id',
            'linkedin_url',
            'github_url'
        ).where('id', id);

        return candidateFiltered;
    },

    async listByUser(user_id) {
        const candidate = await conn('candidate').select(
            'id',
            'user_id',
            'linkedin_url',
            'github_url'
        ).where('user_id', user_id).first();

        return candidate;
    },

    async update(id, data){
        const candidateUpdated = await conn('candidate')
            .where( { id })
            .update(data)
            .returning(['id']);
        
        return candidateUpdated;
    },

    async delete(id) {
        const candidateDeleted = await conn('candidate')
            .where( { id })
            .delete()
            .returning(['id']);

        return candidateDeleted;
    }
}