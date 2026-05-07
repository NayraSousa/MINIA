const express = require('express')
const recruiterController = require('../controllers/RecruiterController')
const authMiddleware = require('../middlewares/authMiddleware')

const recruiterRouter = express.Router();

recruiterRouter.post('/recruiter', authMiddleware, recruiterController.create)
recruiterRouter.get('/recruiter', authMiddleware, recruiterController.listAll)
recruiterRouter.get('/recruiter/:id', authMiddleware, recruiterController.listById)
recruiterRouter.get('recruiter/user/:user_id', authMiddleware, recruiterController.listByUserId)
recruiterRouter.put('/recruiter/:id', authMiddleware, recruiterController.update)
recruiterRouter.delete('recruiter/:id', authMiddleware, recruiterController.delete)

module.exports = recruiterRouter;