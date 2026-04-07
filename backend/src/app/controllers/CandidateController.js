const candidateService = require('../services/CandidateService');

module.exports = {
    async create (request, response) {
        const { user_id, linkedin_url, github_url } = request.body;

        candidate = await candidateService.create(user_id, linkedin_url, github_url);

        return response.status(201).json({ candidate })
    },

    async listAll(request, response) {
        candidates = await candidateService.listAll();
        return response.status(200).json(
            {candidates}
        )
    },

    async listById(request, response) {
        const { id } = request.params;
        const candidateFiltered = await candidateService.listById(id);
        return response.status(200).json({candidateFiltered})
    },

    async listByUser(request, response) {
        const { user_id } = request.params;
        const candidate = await candidateService.listByUser(user_id);
        if(!candidate) return response.status(404).send({ error: 'Candidate not found' })
        return response.status(200).json({ candidate })
    },

    async update(request, response) {
        const { id } = request.params;
        const data = Object.fromEntries(
            Object.entries(request.body).filter(([_, v]) => v !== undefined)
        );

        candidateUpdated = await candidateService.update(id, data);
        return response.status(200).json({candidateUpdated});
    },

    async delete(request, response) {
        const { id } = request.params;
        const candidateDeleted = await candidateService.delete(id);

        return response.status(200).json({candidateDeleted});
    }
}   