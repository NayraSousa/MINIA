const express = require('express');
const analysisRouter = express.Router();
const authMiddleware = require('../middlewares/authMiddleware')


const aiController =
require('../controllers/ResumeAnalysisController');

analysisRouter.post(
    '/ai/analyze',
    authMiddleware,
    aiController.analyze
);

module.exports = analysisRouter;