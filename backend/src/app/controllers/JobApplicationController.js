const jobApplicationService = require('../services/JobApplicationService');
const jobService = require('../services/JobService');
const resumeAnalysisService = require('../services/ai/ResumeAnalysisService');

function compatibilityFromScore(score){
    if(score == null) return 'Não avaliado';
    if(score >= 75) return 'Alta compatibilidade';
    if(score >= 45) return 'Compatibilidade média';
    return 'Baixa compatibilidade';
}

module.exports = {
    async create (request, response) {
        const { job_id, candidate_id, curriculum } = request.body;
        const status = "Inscrito";

        const job = await jobService.listById(job_id);
        if(!job || job.length === 0){
            return response.status(404).json({ error: 'Vaga não encontrada' });
        }

        let ai_score = null;
        if(curriculum && curriculum.trim().length > 0 && job[0].description){
            try{
                const analysis = await resumeAnalysisService.analyze(curriculum, job[0].description);
                ai_score = analysis?.score ?? null;
            }catch(err){
                ai_score = null;
            }
        }

        const jobApplication = await jobApplicationService.create(
            candidate_id, job_id, curriculum, status, ai_score
        );

        return response.status(201).json({
            jobApplication: {
                ...jobApplication,
                ai_score,
                compatibility: compatibilityFromScore(ai_score)
            }
        });
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

    async listByJobId(request, response) {
        const { job_id } = request.params;
        const jobApplications = await jobApplicationService.listByJobId(job_id);
        const enriched = jobApplications.map(app => ({
            ...app,
            compatibility: compatibilityFromScore(app.ai_score)
        }));
        return response.status(200).json({ jobApplications: enriched });
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
