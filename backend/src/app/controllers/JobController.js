const jobService = require('../services/JobService');

module.exports = {
    async create (request, response) {
        const { name, description } = request.body;
        const recruiter_id = "f30b2dde-7ce6-4913-80b3-00aee94daf7b";
        const company_id = "31932ba7-5560-44dc-9dc1-51e5cfebb16e";
        const created_by = "Arthur"

        job = await jobService.create(name, description, recruiter_id, company_id, created_by);

        return response.status(201).json(
            {
                mensagem: {
                    "Job Created": {
                        job
                    }
                }
            }
        )
    },

    async listAll(request, response) {
        jobs = await jobService.listAll();
        return response.status(200).json(
            {jobs}
        )
    },

    async listById(request, response) {
        const { id } = request.params;
        const jobFiltered = await jobService.listById(id);
        return response.status(200).json({jobFiltered})
    },

    async update(request, response) {
        const { id } = request.params;
        const data = Object.fromEntries(
            Object.entries(request.body).filter(([_, v]) => v !== undefined)
        );

        jobUpdated = await jobService.update(id, data);
        return response.status(200).json({jobUpdated});
    },

    async delete(request, response) {
        const { id } = request.params;
        const jobDeleted = await jobService.delete(id);

        return response.status(200).json({jobDeleted});
    }
}