const recruiterService = require('../services/RecruiterService');
const { listById } = require('./CandidateController');

module.exports = {
    async create(request, response) {
        const { user_id, company_id, departament, responsability } = request.body;

        recruiter = await recruiterService.create(user_id, company_id, departament, responsability);
        return response.status(201).json({ recruiter });
    },

    async listAll(request, response) {
        recruiters = await recruiterService.listAll();

        return response.status(200).json( { recruiters });
    },

    async listById(request, response) {
        const { id } = request.params;
        const recruiteriltered = await recruiterService.listById(id);

        return response.status(200).json({recruiteriltered})
    },

    async listByUserId(request, response) {
        const { user_id } = request.params;
        const recruiter = await recruiterService.listByUserId(user_id);

        if (!recruiter) return response.status(404).send({ error: 'Recruiter not found' });
        return response.status(200).json({ recruiter });
    },

    async update(request, response) {
        const { id } = request.params;
        const data = Object.fromEntries(
            Object.entries(request.body).filter(([_, v]) => v !== undefined)
        );

        const recruiterUpdated = await recruiterService.update(id, data);
        return response.status(200).json({recruiterUpdated});
    },

    async delete(request, response) {
        const { id } = request.params;
        const recruiterDeleted = await recruiterService.delete(id);

        return response.status(200).json({recruiterDeleted});
    }
}