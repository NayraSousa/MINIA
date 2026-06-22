const express = require('express')
const jobApplicationController = require('../controllers/JobApplicationController')
const authMiddleware = require('../middlewares/authMiddleware')

const jobApplicationRouter = express.Router();

jobApplicationRouter.post('/job_application', authMiddleware, jobApplicationController.create)
jobApplicationRouter.get('/job_application', authMiddleware, jobApplicationController.listAll)
jobApplicationRouter.get('/job_application/job/:job_id', authMiddleware, jobApplicationController.listByJobId)
jobApplicationRouter.get('/job_application/:id', authMiddleware, jobApplicationController.listById)
jobApplicationRouter.put('/job_application/:id', authMiddleware, jobApplicationController.update)
jobApplicationRouter.delete('/job_application/:id', authMiddleware, jobApplicationController.delete)

module.exports = jobApplicationRouter;