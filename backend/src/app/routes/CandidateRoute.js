const express = require('express')
const candidateController = require('../controllers/CandidateController')
const authMiddleware = require('../middlewares/authMiddleware')

const candidateRouter = express.Router();

candidateRouter.post('/candidate', authMiddleware, candidateController.create)
candidateRouter.get('/candidate', authMiddleware, candidateController.listAll)
candidateRouter.get('/candidate/:id', authMiddleware, candidateController.listById)
candidateRouter.get('/candidate/user/:user_id', authMiddleware, candidateController.listByUser)
candidateRouter.put('/candidate/:id', authMiddleware, candidateController.update)
candidateRouter.delete('/candidate/:id', authMiddleware, candidateController.delete)

module.exports = candidateRouter;
