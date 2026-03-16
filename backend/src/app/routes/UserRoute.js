const express = require('express')
const userController = require('../controllers/UserController')

const userRouter = express.Router();

userRouter.get('/user', userController.listAll)
userRouter.get('/user/:id', userController.listById)
userRouter.post('/user', userController.create)

module.exports = userRouter;