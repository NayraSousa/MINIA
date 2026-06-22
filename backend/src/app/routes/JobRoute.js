const express = require('express')
const jobController = require('../controllers/JobController')
const authMiddleware = require('../middlewares/authMiddleware')

const jobRouter = express.Router();

jobRouter.post('/job', authMiddleware, jobController.create)
jobRouter.get('/job', authMiddleware, jobController.listAll)
jobRouter.get('/job/recruiter/:recruiter_id', authMiddleware, jobController.listByRecruiter)
jobRouter.get('/job/:id', authMiddleware, jobController.listById)
jobRouter.put('/job/:id', authMiddleware, jobController.update)
jobRouter.delete('/job/:id', authMiddleware, jobController.delete)

module.exports = jobRouter;