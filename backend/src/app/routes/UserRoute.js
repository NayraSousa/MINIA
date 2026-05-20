const express = require('express')
const userController = require('../controllers/UserController')
const authMiddleware = require('../middlewares/authMiddleware')

const userRouter = express.Router();

userRouter.post('/user', userController.create)
userRouter.get('/user', authMiddleware, userController.listAll)
userRouter.get('/user/:id', authMiddleware, userController.listById)
userRouter.put('/user/:id', authMiddleware, userController.update)
userRouter.delete('/user/:id', authMiddleware, userController.delete)

module.exports = userRouter;