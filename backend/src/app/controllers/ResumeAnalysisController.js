const aiService =
require('../services/ai/ResumeAnalysisService');

module.exports = {

    async analyze(req,res){

        const {
            resumeText,
            jobDescription
        } = req.body;

        const result =
            await aiService.analyze(
                resumeText,
                jobDescription
            );

        return res.json(result);

    }

}