const express = require('express')
const authController = require('../controllers/AuthController')

const authRoute = express.Router()

authRoute.post("/auth", authController.auth)

module.exports = authRoute
