const jobService = require('../services/JobService');
const recruiterService = require('../services/RecruiterService');
const userService = require('../services/UserService');

module.exports = {
    async create (request, response) {
        const { name, description , userId} = request.body;

        const recruiter = await recruiterService.listByUserId(userId);
        if(!recruiter){
            return response.status(404).json({ error: 'Perfil de recrutador não encontrado' });
        }

        const userList = await userService.listById(userId);
        const createdBy = (userList && userList[0] && userList[0].name) || null;

        const job = await jobService.create(
            name,
            description,
            recruiter[0].id,
            recruiter[0].company_id,
            createdBy
        );

        return response.status(201).json({ job });
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

    async listByRecruiter(request, response) {
        const { recruiter_id } = request.params;
        const jobs = await jobService.listByRecruiterId(recruiter_id);
        return response.status(200).json({ jobs });
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