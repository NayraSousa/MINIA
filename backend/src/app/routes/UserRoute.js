const express = require('express')
const userController = require('../controllers/UserController')

const userRouter = express.Router();

userRouter.post('/user', userController.create)
userRouter.get('/user', userController.listAll)
userRouter.get('/user/:id', userController.listById)
userRouter.put('/user/:id', userController.update)
userRouter.delete('/user/:id', userController.delete)

module.exports = userRouter;