const jobApplicationService = require('../services/JobApplicationService');

module.exports = {
    async create (request, response) {
        const { job_id } = request.body;
        const candidate_id = "bea02554-98fa-4416-a73c-78fe6b197ba4";
        const created_at = new Date();
        const status = "Inscrito"
        const ai_score = "99.9"

        jobApplication = await jobApplicationService.create(candidate_id, job_id, status, ai_score, created_at);

        return response.status(201).json(
            {
                mensagem: {
                    "Job Created": {
                        jobApplication
                    }
                }
            }
        )
    },

    async listAll(request, response) {
        jobApplications = await jobApplicationService.listAll();
        return response.status(200).json(
            {jobApplications}
        )
    },

    async listById(request, response) {
        const { id } = request.params;
        const jobApplicationFiltered = await jobApplicationService.listById(id);
        return response.status(200).json({jobApplicationFiltered})
    },

    async update(request, response) {
        const { id } = request.params;
        const data = Object.fromEntries(
            Object.entries(request.body).filter(([_, v]) => v !== undefined)
        );

        jobApplicationUpdated = await jobApplicationService.update(id, data);
        return response.status(200).json({jobApplicationUpdated});
    },

    async delete(request, response) {
        const { id } = request.params;
        const jobApplicationDeleted = await jobApplicationService.delete(id);

        return response.status(200).json({jobApplicationDeleted});
    }
}