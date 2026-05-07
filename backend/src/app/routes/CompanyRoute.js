const express = require('express')
const companyController = require('../controllers/CompanyController')
const authMiddleware = require('../middlewares/authMiddleware')

const companyRouter = express.Router();

companyRouter.post('/company', authMiddleware, companyController.create)
companyRouter.get('/company', authMiddleware, companyController.listAll)
companyRouter.get('/company/:id', authMiddleware, companyController.listById)
companyRouter.put('/company/:id', authMiddleware, companyController.update)
companyRouter.delete('company/:id', authMiddleware, companyController.delete)

module.exports = companyRouter;